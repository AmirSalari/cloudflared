package tunneldns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/chris-wood/odoh"
	"github.com/cisco/go-hpke"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
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
	client     *http.Client
	endpoint   *url.URL
	bootstraps []string
	logger     logger.Service
	protocol   string
	isProxy    bool
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
	queryBuf, err := query.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack DNS query")
	}
	var randomTargetChosen string
	var targetPublicKey odoh.ObliviousDNSPublicKey
	if protocol == "ODOH" {
		randomTargetChosen = u.odohProxyState.targets[mathrand.Intn(len(u.odohProxyState.targets))]
		log.Printf("%v %v", u.odohProxyState, randomTargetChosen)
		targetPublicKey = u.odohProxyState.targetKeys[randomTargetChosen]
	}

	if len(query.Question) > 0 && query.Question[0].Name == fmt.Sprintf("%s.", u.endpoint.Hostname()) {
		for _, bootstrap := range u.bootstraps {
			endpoint, client, err := configureBootstrap(bootstrap)
			if err != nil {
				u.logger.Errorf("failed to configure bootstrap upstream %s: %s", bootstrap, err)
				continue
			}
			msg, err := exchange(queryBuf, query.Id, endpoint, client, protocol, randomTargetChosen, targetPublicKey, u.logger)
			if err != nil {
				u.logger.Errorf("failed to connect to a bootstrap upstream %s: %s", bootstrap, err)
				continue
			}
			return msg, nil
		}
		return nil, fmt.Errorf("failed to reach any bootstrap upstream: %v", u.bootstraps)
	}
	u.logger.Infof("Using non bootstrap value %s", u.endpoint)

	return exchange(queryBuf, query.Id, u.endpoint, u.client, protocol, randomTargetChosen, targetPublicKey, u.logger)
}

const (
	TARGET_HTTP_MODE = "https"
	PROXY_HTTP_MODE = "https"
	OBLIVIOUS_DOH = "application/oblivious-dns-message"
)

func prepareHttpRequest(serializedBody []byte, useProxy bool, targetIP string, proxy string, protocol string) (req *http.Request, err error) {
	var baseurl string
	var queries url.Values

	if useProxy != true {
		baseurl = fmt.Sprintf("%s://%s/%s", TARGET_HTTP_MODE, targetIP, "dns-query")
		req, err = http.NewRequest(http.MethodPost, baseurl,  bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
	} else {
		baseurl = proxy
		req, err = http.NewRequest(http.MethodPost, baseurl,  bytes.NewBuffer(serializedBody))
		queries = req.URL.Query()
		queries.Add("targethost", targetIP)
		queries.Add("targetpath", "/dns-query")
	}

	req.Header.Set("Content-Type", protocol)
	req.URL.RawQuery = queries.Encode()

	return req, err
}

func prepareOdohQuestion(dnsQuery []byte, key []byte, publicKey odoh.ObliviousDNSPublicKey) (res []byte, err error) {
	odohQuery := odoh.ObliviousDNSQuery{
		ResponseKey: key,
		DnsMessage:  dnsQuery,
	}

	odnsMessage, err := publicKey.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("Unable to Encrypt oDoH Question with provided Public Key of Resolver")
		return nil, err
	}

	return odnsMessage.Marshal(), nil
}

func createOdohQueryResponse(serializedOdohDnsQueryString []byte, useProxy bool, targetIP string, proxy string, client *http.Client) (response *odoh.ObliviousDNSMessage, err error) {
	req, err := prepareHttpRequest(serializedOdohDnsQueryString, useProxy, targetIP, proxy, OBLIVIOUS_DOH)

	if err != nil {
		log.Fatalln(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	responseHeader := resp.Header.Get("Content-Type")
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response body.")
		log.Fatalln(err)
	}
	if responseHeader != OBLIVIOUS_DOH {
		log.Printf("[WARN] The returned response does not have the %v Content-Type from %v with response %v\n", OBLIVIOUS_DOH, targetIP, string(bodyBytes))
		return &odoh.ObliviousDNSMessage{
			MessageType:      odoh.ResponseType,
			KeyID:            []byte{},
			EncryptedMessage: []byte{},
		}, errors.New(fmt.Sprintf("Did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes)))
	}

	hexBodyBytes := hex.EncodeToString(bodyBytes)
	log.Printf("[ODOH] Hex Encrypted Response : %v %v\n", hexBodyBytes, string(bodyBytes))

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)

	if err != nil {
		log.Printf("Unable to Unmarshal the Encrypted ODOH Response")
		return nil, err
	}

	return odohQueryResponse, nil
}

func validateEncryptedResponse(message *odoh.ObliviousDNSMessage, key []byte) (response *dns.Msg, err error) {
	odohResponse := odoh.ObliviousDNSResponse{ResponseKey: key}

	responseMessageType := message.MessageType
	if responseMessageType != odoh.ResponseType {
		log.Fatalln("[ERROR] The data obtained from the server is not of the response type")
	}

	encryptedResponse := message.EncryptedMessage

	kemID := hpke.DHKEM_X25519
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AESGCM128

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)

	if err != nil {
		log.Fatalln("Unable to initialize HPKE Cipher Suite", err)
	}

	// The following lines are hardcoded on the server side for `aad`
	responseKeyId := []byte{0x00, 0x00}
	aad := append([]byte{0x02}, responseKeyId...) // message_type = 0x02, with an empty keyID

	decryptedResponse, err := odohResponse.DecryptResponse(suite, aad, encryptedResponse)

	if err != nil {
		log.Printf("Unable to decrypt the obtained response using the symmetric key sent.")
	}

	log.Printf("[ODOH] [Decrypted Response] : %v\n", decryptedResponse)

	dnsBytes, err := parseDnsResponse(decryptedResponse)
	if err != nil {
		log.Printf("Unable to parse DNS bytes after decryption of the message from target server.")
		return nil, err
	}

	return dnsBytes, err
}

func parseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func RetrievePublicKey(ip string, client *http.Client) (odoh.ObliviousDNSPublicKey, error) {
	req, err := http.NewRequest(http.MethodGet, "https://" + ip + "/pk", nil)
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	odohPublicKey := odoh.UnMarshalObliviousDNSPublicKey(bodyBytes)

	return odohPublicKey, err
}

func exchangeOdohWireFormat(msg []byte, endpoint *url.URL, targetChosen string, pkOfChosenTarget odoh.ObliviousDNSPublicKey, client *http.Client) ([]byte, error) {
	keyChosen := make([]uint8, 16)
	_, err := rand.Read(keyChosen)

	if err != nil {
		log.Fatalf("Unable to generate random bytes for symmetric key")
	}

	serializedOdohQueryMessage, err := prepareOdohQuestion(msg, keyChosen, pkOfChosenTarget)
	odohMessage, err := createOdohQueryResponse(serializedOdohQueryMessage, true, targetChosen, endpoint.String(), client)

	if err != nil {
		log.Printf("Unable to receive ODOH Response")
	}

	dnsAnswer, err := validateEncryptedResponse(odohMessage, keyChosen)
	if err != nil || dnsAnswer == nil {
		log.Printf("Unable to retrieve a correct DNS Answer")
		return nil, err
	}
	dnsAnswerBytes, err := dnsAnswer.Pack()
	return dnsAnswerBytes, nil
}

func exchange(msg []byte, queryID uint16, endpoint *url.URL, client *http.Client, protocol string, target string, targetPublicKey odoh.ObliviousDNSPublicKey, logger logger.Service) (*dns.Msg, error) {
	// No content negotiation for now, use DNS wire format
	var buf []byte
	var backendErr error
	if protocol == "ODOH" {
		buf, backendErr = exchangeOdohWireFormat(msg, endpoint, target, targetPublicKey, client)
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
	tls := &tls.Config{ServerName: hostname}
	transport := &http.Transport{
		TLSClientConfig:    tls,
		DisableCompression: true,
		MaxIdleConns:       1,
		Proxy:              http.ProxyFromEnvironment,
	}
	http2.ConfigureTransport(transport)

	return &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
}
