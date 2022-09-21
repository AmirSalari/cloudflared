package tunneldns

import (
	"encoding/json"
	"github.com/cloudflare/cloudflared/logger"
	odoh "github.com/cloudflare/odoh-go"
	"log"
	"net/http"
)

type proxyServer struct {
	client     *http.Client
	targetKeys map[string]odoh.ObliviousDoHConfigContents
	proxies    []string
	targets    []string
}

type DiscoveryServiceResponse struct {
	Proxies []string `json:"proxies"`
	Targets []string `json:"targets"`
}

func DiscoverProxiesAndTargets(hostname string, client *http.Client) (response DiscoveryServiceResponse, err error) {
	req, err := http.NewRequest(http.MethodGet, hostname, nil)
	if err != nil {
		log.Fatalf("Unable to discover the proxies and targets")
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to obtain a response from the discovery service")
	}
	defer resp.Body.Close()

	var data DiscoveryServiceResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&data)
	if err != nil {
		log.Fatalf("Unable to decode the obtained JSON response from the Discovery service %v\n", err)
	}
	return data, nil
}

func (p *proxyServer) bootstrap(discoveryURLs []string, logger logger.Service) {
	p.targets = make([]string, 0)
	p.proxies = make([]string, 0)
	p.targetKeys = make(map[string]odoh.ObliviousDoHConfigContents)

	p.targets = append(p.targets, "odoh.cloudflare-dns.com")
	p.proxies = append(p.proxies, "localhost:8080")

	for _, target := range p.targets {
		configs, err := fetchTargetConfigs(target)
		if err != nil {
			logger.Fatalf("Unable to obtain the public Key from %v. Error %v", target, err)
		}
		if len(configs.Configs) == 0 {
			logger.Fatalf("No configuration obtained for the target  %v", target)
		}
		config := configs.Configs[0]
		logger.Infof("Adding ODOH Target - url: %s", target)
		//targetUrl := fmt.Sprintf("https://%s/dns-query", target)
		p.targets = append(p.targets, target)
		p.targetKeys[target] = config.Contents
		logger.Infof("Target [%v] ConfigContents : %v", target, config.Contents)
	}

	//for _, discoveryService := range discoveryURLs {
	//	availableServices, err := DiscoverProxiesAndTargets(discoveryService, p.client)
	//	if err != nil {
	//		logger.Error("Unable to discover ODOH Targets/Proxies")
	//	}
	//	for _, proxy := range availableServices.Proxies {
	//		proxyUrl := fmt.Sprintf("%s", proxy)
	//		p.proxies = append(p.proxies, proxyUrl)
	//	}
	//	if err != nil {
	//		logger.Fatalf("Unable to discover the services available.")
	//	}
	//	// Obtain all the keys for the targets.
	//	targets := availableServices.Targets
	//	for _, target := range targets {
	//		configs, err := fetchTargetConfigs(target)
	//		if err != nil {
	//			logger.Fatalf("Unable to obtain the public Key from %v. Error %v", target, err)
	//		}
	//		if len(configs.Configs) == 0 {
	//			logger.Fatalf("No configuration obtained for the target  %v", target)
	//		}
	//		config := configs.Configs[0]
	//		logger.Infof("Adding ODOH Target - url: %s", target)
	//		//targetUrl := fmt.Sprintf("https://%s/dns-query", target)
	//		p.targets = append(p.targets, target)
	//		p.targetKeys[target] = config.Contents
	//		logger.Infof("Target [%v] ConfigContents : %v", target, config.Contents)
	//	}
	//}
}
