package tunneldns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	odoh "github.com/cloudflare/odoh-go"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloudflare/cloudflared/logger"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"
)

const (
	defaultTimeout = 5 * time.Second
)

// UpstreamHTTPS is the upstream implementation for DNS over HTTPS service
type UpstreamHTTPS struct {
	client         *http.Client
	endpoint       *url.URL
	bootstraps     []string
	logger         logger.Service
	protocol       string
	isProxy        bool
	odohProxyState *proxyServer
}

// NewUpstreamHTTPS creates a new DNS over HTTPS upstream from endpoint
func NewUpstreamHTTPS(endpoint string, bootstraps []string, protocol string, isProxy bool, odohProxy *proxyServer, logger logger.Service) (Upstream, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	return &UpstreamHTTPS{client: configureClient(u.Hostname()), endpoint: u, bootstraps: bootstraps, protocol: protocol, isProxy: isProxy, odohProxyState: odohProxy, logger: logger}, nil
}

// Exchange provides an implementation for the Upstream interface
func (u *UpstreamHTTPS) Exchange(ctx context.Context, query *dns.Msg, protocol string) (*dns.Msg, error) {
	proxy := ""
	queryBuf, err := query.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack DNS query")
	}
	var randomTargetChosen string
	var targetConfigContents odoh.ObliviousDoHConfigContents
	if protocol == "ODOH" {
		proxy = u.odohProxyState.proxies[mathrand.Intn(len(u.odohProxyState.proxies))]
		randomTargetChosen = u.odohProxyState.targets[mathrand.Intn(len(u.odohProxyState.targets))]
		targetConfigContents = u.odohProxyState.targetKeys[randomTargetChosen]
		log.Printf("Choosing %v and %v Proxy-Target pair", proxy, randomTargetChosen)
	}

	//if len(query.Question) > 0 && query.Question[0].Name == fmt.Sprintf("%s.", u.endpoint.Hostname()) {
	//	for _, bootstrap := range u.bootstraps {
	//		endpoint, client, err := configureBootstrap(bootstrap)
	//		if err != nil {
	//			u.logger.Errorf("failed to configure bootstrap upstream %s: %s", bootstrap, err)
	//			continue
	//		}
	//		msg, err := exchange(queryBuf, query.Id, endpoint, client, protocol, proxy, randomTargetChosen, targetConfigContents, u.logger)
	//		if err != nil {
	//			u.logger.Errorf("failed to connect to a bootstrap upstream %s: %s", bootstrap, err)
	//			continue
	//		}
	//		return msg, nil
	//	}
	//	return nil, fmt.Errorf("failed to reach any bootstrap upstream: %v", u.bootstraps)
	//}
	//u.logger.Infof("Using non bootstrap value %s with client %p for %v", u.endpoint, &u.client, query.Question)

	return exchange(queryBuf, query.Id, u.endpoint, u.client, protocol, proxy, randomTargetChosen, targetConfigContents, u.logger)
}

const (
	TARGET_HTTP_MODE = "https"
	PROXY_HTTP_MODE = "https"
	OBLIVIOUS_DOH = "application/oblivious-dns-message"
	DEFAULT_DOH_SERVER        = "cloudflare-dns.com"
	ODOH_CONFIG_WELLKNOWN_URL = "/.well-known/odohconfigs"
)

func prepareHttpRequest(serializedBody []byte, useProxy bool, targetIP string, proxy string) (req *http.Request, err error) {
	var baseurl string
	var queries url.Values

	if useProxy != true {
		baseurl = fmt.Sprintf("%s://%s/%s", TARGET_HTTP_MODE, targetIP, "dns-query")
		req, err = http.NewRequest(http.MethodPost, baseurl, bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
	} else {
		log.Printf("Using proxy to prepare HTTP Request [%v-%v]", proxy, targetIP)
		baseurl = fmt.Sprintf("%s://%s/%s", PROXY_HTTP_MODE, proxy, "proxy")
		req, err = http.NewRequest(http.MethodPost, baseurl, bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
		queries.Add("targethost", targetIP)
		queries.Add("targetpath", "/dns-query")
	}

	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.URL.RawQuery = queries.Encode()

	return req, err
}

//func createOdohQueryResponse(serializedOdohDnsQueryString []byte, useProxy bool, targetIP string, proxy string, client *http.Client) (response *odoh.ObliviousDNSMessage, err error) {
//	req, err := prepareHttpRequest(serializedOdohDnsQueryString, useProxy, targetIP, proxy, OBLIVIOUS_DOH)
//
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	resp, err := client.Do(req)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	responseHeader := resp.Header.Get("Content-Type")
//	bodyBytes, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		log.Println("Failed to read response body.")
//		log.Fatalln(err)
//	}
//	if responseHeader != OBLIVIOUS_DOH {
//		log.Printf("[WARN] The returned response does not have the %v Content-Type from %v with response %v\n", OBLIVIOUS_DOH, targetIP, string(bodyBytes))
//		return &odoh.ObliviousDNSMessage{
//			MessageType:      odoh.ResponseType,
//			KeyID:            []byte{},
//			EncryptedMessage: []byte{},
//		}, errors.New(fmt.Sprintf("Did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes)))
//	}
//
//	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
//
//	if err != nil {
//		log.Printf("Unable to Unmarshal the Encrypted ODOH Response")
//		return nil, err
//	}
//
//	return odohQueryResponse, nil
//}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func fetchTargetConfigsFromWellKnown(targetName string) (odoh.ObliviousDoHConfigs, error) {
	req, err := http.NewRequest(http.MethodGet, TARGET_HTTP_MODE+"://"+targetName+ODOH_CONFIG_WELLKNOWN_URL, nil)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	return odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
}

func createPlainQueryResponse(hostname string, serializedDnsQueryString []byte) (response *dns.Msg, err error) {
	client := http.Client{}
	queryUrl := fmt.Sprintf(TARGET_HTTP_MODE+"://%s/dns-query", hostname)
	req, err := http.NewRequest(http.MethodGet, queryUrl, nil)
	if err != nil {
		log.Fatalln(err)
	}

	queries := req.URL.Query()
	encodedString := base64.RawURLEncoding.EncodeToString(serializedDnsQueryString)
	queries.Add("dns", encodedString)
	req.Header.Set("Content-Type", "application/dns-message")
	req.URL.RawQuery = queries.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	dnsBytes, err := parseDnsResponse(bodyBytes)

	return dnsBytes, nil
}

func fetchTargetConfigsFromDNS(targetName string) (odoh.ObliviousDoHConfigs, error) {
	if !strings.HasSuffix(targetName, ".") {
		targetName = targetName + "."
	}

	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(targetName, dns.TypeHTTPS)
	dnsQuery.RecursionDesired = true
	packedDnsQuery, err := dnsQuery.Pack()
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	response, err := createPlainQueryResponse(DEFAULT_DOH_SERVER, packedDnsQuery)
	if err != nil {
		return odoh.ObliviousDoHConfigs{}, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return odoh.ObliviousDoHConfigs{}, errors.New(fmt.Sprintf("DNS response failure: %v", response.Rcode))
	}

	for _, answer := range response.Answer {
		httpsResponse, ok := answer.(*dns.HTTPS)
		if ok {
			for _, value := range httpsResponse.Value {
				if value.Key() == 32769 {
					parameter, ok := value.(*dns.SVCBLocal)
					if ok {
						odohConfigs, err := odoh.UnmarshalObliviousDoHConfigs(parameter.Data)
						if err == nil {
							return odohConfigs, nil
						}
					}
				}
			}
		}
	}

	return odoh.ObliviousDoHConfigs{}, nil
}

func fetchTargetConfigs(targetName string) (odoh.ObliviousDoHConfigs, error) {
	//odohConfigs, err := fetchTargetConfigsFromDNS(targetName)
	//if err == nil {
	//	fmt.Printf("%v\n", odohConfigs)
	//	return odohConfigs, err
	//}

	// Fall back to the well-known endpoint if we can't read from DNS
	return fetchTargetConfigsFromWellKnown(targetName)
}

//func RetrievePublicKey(ip string, client *http.Client) (odoh.ObliviousDNSPublicKey, error) {
//	req, err := http.NewRequest(http.MethodGet, "https://" + ip + "/pk", nil)
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	resp, err := client.Do(req)
//	if err != nil {
//		log.Fatalln(err)
//	}
//	bodyBytes, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	odohPublicKey := odoh.UnMarshalObliviousDNSPublicKey(bodyBytes)
//
//	return odohPublicKey, err
//}

func createOdohQuestion(dnsMessage []byte, publicKey odoh.ObliviousDoHConfigContents) (odoh.ObliviousDNSMessage, odoh.QueryContext, error) {
	odohQuery := odoh.CreateObliviousDNSQuery(dnsMessage, 0)
	odnsMessage, queryContext, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, odoh.QueryContext{}, err
	}

	return odnsMessage, queryContext, nil
}

func resolveObliviousQuery(query odoh.ObliviousDNSMessage, useProxy bool, targetIP string, proxy string, client *http.Client) (response odoh.ObliviousDNSMessage, err error) {
	serializedQuery := query.Marshal()
	req, err := prepareHttpRequest(serializedQuery, useProxy, targetIP, proxy)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	responseHeader := resp.Header.Get("Content-Type")
	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}
	if responseHeader != OBLIVIOUS_DOH {
		return odoh.ObliviousDNSMessage{}, errors.New(fmt.Sprintf("Did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes)))
	}

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	return odohQueryResponse, nil
}

func validateEncryptedResponse(message odoh.ObliviousDNSMessage, queryContext odoh.QueryContext) (response []byte, err error) {
	decryptedResponse, err := queryContext.OpenAnswer(message)
	if err != nil {
		return nil, err
	}

	//dnsBytes, err := parseDnsResponse(decryptedResponse)
	//if err != nil {
	//	return nil, err
	//}

	return decryptedResponse, nil
}

func exchangeOdohWireFormat(msg []byte, endpoint *url.URL, targetChosen string, proxy string, pkOfChosenTarget odoh.ObliviousDoHConfigContents, client *http.Client) ([]byte, error) {
	dnsQuery := new(dns.Msg)
	dnsQuery.Unpack(msg)
	log.Printf("Question: %v", dnsQuery.Question)
	shouldUseProxy := false
	if proxy != "" {
		shouldUseProxy = true
	}

	odohQuery, queryContext, err := createOdohQuestion(msg, pkOfChosenTarget)
	if err != nil {
		log.Fatalf("createOdohQuestion failed: %v", err)
	}

	if err != nil {
		log.Printf("Unable to receive ODOH Response")
	}

	odohClient := http.Client{}
	odohMessage, err := resolveObliviousQuery(odohQuery, shouldUseProxy, targetChosen, proxy, &odohClient)

	dnsAnswer, err := validateEncryptedResponse(odohMessage, queryContext)
	return dnsAnswer, nil
}

func exchange(msg []byte, queryID uint16, endpoint *url.URL, client *http.Client, protocol string, proxy string, target string, targetPublicKey odoh.ObliviousDoHConfigContents, logger logger.Service) (*dns.Msg, error) {
	// No content negotiation for now, use DNS wire format
	var buf []byte
	var backendErr error
	if protocol == "ODOH" {
		buf, backendErr = exchangeOdohWireFormat(msg, endpoint, target, proxy, targetPublicKey, client)
	} else {
		buf, backendErr = exchangeWireformat(msg, endpoint, client)
	}
	if backendErr == nil {
		response := &dns.Msg{}
		if err := response.Unpack(buf); err != nil {
			return nil, errors.Wrap(err, "failed to unpack DNS response from body")
		}

		response.Id = queryID
		return response, nil
	}

	logger.Errorf("failed to connect to an HTTPS backend %q: %s", endpoint, backendErr)
	return nil, backendErr
}

// Perform message exchange with the default UDP wireformat defined in current draft
// https://datatracker.ietf.org/doc/draft-ietf-doh-dns-over-https
func exchangeWireformat(msg []byte, endpoint *url.URL, client *http.Client) ([]byte, error) {
	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(msg))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create an HTTPS request")
	}

	req.Header.Add("Content-Type", "application/dns-message")
	req.Host = endpoint.Host

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform an HTTPS request")
	}

	// Check response status code
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status code %d", resp.StatusCode)
	}

	// Read wireformat response from the body
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the response body")
	}

	return buf, nil
}

func configureBootstrap(bootstrap string) (*url.URL, *http.Client, error) {
	b, err := url.Parse(bootstrap)
	if err != nil {
		return nil, nil, err
	}
	if ip := net.ParseIP(b.Hostname()); ip == nil {
		return nil, nil, fmt.Errorf("bootstrap address of %s must be an IP address", b.Hostname())
	}

	return b, configureClient(b.Hostname()), nil
}

// configureClient will configure a HTTPS client for upstream DoH requests
func configureClient(hostname string) *http.Client {
	// Update TLS and HTTP client configuration
	//tls := &tls.Config{ServerName: hostname}
	transport := &http.Transport{
		//TLSClientConfig:    tls,
		//DisableCompression: true,
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
		Proxy:               http.ProxyFromEnvironment,
	}
	http2.ConfigureTransport(transport)

	return &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
}
