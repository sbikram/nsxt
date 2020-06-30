/* Copyright © 2017 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: MPL-2.0 */

package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	api "github.com/vmware/go-vmware-nsxt"
	nsxt "github.com/vmware/go-vmware-nsxt"
	"github.com/vmware/go-vmware-nsxt/manager"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/core"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/protocol/client"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/security"
	gm_infra "github.com/vmware/vsphere-automation-sdk-go/services/nsxt-gm/global_infra"
	gm_model "github.com/vmware/vsphere-automation-sdk-go/services/nsxt-gm/model"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/infra"
	"github.com/vmware/vsphere-automation-sdk-go/services/nsxt/model"
)

var defaultRetryOnStatusCodes = []int{429, 503}
var policySite = "default"

// Provider configuration that is shared for policy and MP
type commonProviderConfig struct {
	RemoteAuth             bool
	ToleratePartialSuccess bool
}

type nsxtClients struct {
	CommonConfig commonProviderConfig
	// NSX Manager client - based on go-vmware-nsxt SDK
	NsxtClient *nsxt.APIClient
	// Data for NSX Policy client - based on vsphere-automation-sdk-go SDK
	// First offering of Policy SDK does not support concurrent
	// operations in single connector. In order to avoid heavy locks,
	// we are allocating connector per provider operation.
	// TODO: when concurrency support is introduced policy client,
	// change this code to allocate single connector for all provider
	// operations.
	PolicySecurityContext  *core.SecurityContextImpl
	PolicyHTTPClient       *http.Client
	Host                   string
	PolicyEnforcementPoint string
	PolicySite             string
	PolicyGlobalManager    bool
}

func configureNsxtClient(clients *nsxtClients) error {
	clientAuthCertFile := os.Getenv("CLIENT_AUTH_CERT_FILE")
	clientAuthKeyFile := os.Getenv("CLIENT_AUTH_KEY_FILE")
	vmcToken := ""

	if len(vmcToken) > 0 {
		return nil
	}

	needCreds := true
	if len(clientAuthCertFile) > 0 {
		if len(clientAuthKeyFile) == 0 {
			return fmt.Errorf("Please provide key file for client certificate")
		}
		needCreds = false
	}

	insecure := true
	username := os.Getenv("NSXT_USERNAME")
	password := os.Getenv("NSXT_PASSWORD")

	if needCreds {
		if username == "" {
			return fmt.Errorf("username must be provided")
		}

		if password == "" {
			return fmt.Errorf("password must be provided")
		}
	}

	host := os.Getenv("NSXT_MANAGER_HOST")

	if host == "" {
		return fmt.Errorf("NSXT Manager hostIP must be provided")
	}

	caFile := os.Getenv("CA_CERT_FILE")

	maxRetries := 3
	retryMinDelay := 10 // milliseconds
	retryMaxDelay := 10 // milliseconds

	// statuses := d.Get("retry_on_status_codes").([]interface{})
	// if len(statuses) == 0 {
	// 	// Set to the defaults if empty
	// 	for _, val := range defaultRetryOnStatusCodes {
	// 		statuses = append(statuses, val)
	// 	}
	// }
	// retryStatuses := make([]int, 0, len(statuses))
	// for _, s := range statuses {
	// 	retryStatuses = append(retryStatuses, s.(int))
	// }

	retriesConfig := nsxt.ClientRetriesConfiguration{
		MaxRetries:    maxRetries,
		RetryMinDelay: retryMinDelay,
		RetryMaxDelay: retryMaxDelay,
		//RetryOnStatuses: retryStatuses,
	}

	cfg := nsxt.Configuration{
		BasePath:             "/api/v1",
		Host:                 host,
		Scheme:               "https",
		UserAgent:            "itp-nsxt-configurator/1.0",
		UserName:             username,
		Password:             password,
		RemoteAuth:           clients.CommonConfig.RemoteAuth,
		ClientAuthCertFile:   clientAuthCertFile,
		ClientAuthKeyFile:    clientAuthKeyFile,
		CAFile:               caFile,
		Insecure:             insecure,
		RetriesConfiguration: retriesConfig,
	}

	nsxClient, err := nsxt.NewAPIClient(&cfg)
	if err != nil {
		return err
	}

	clients.NsxtClient = nsxClient

	return nil // initNSXVersion(nsxClient)
}

func getNSXVersion(nsxClient *api.APIClient) (string, string, error) {
	nodeProperties, resp, err := nsxClient.NsxComponentAdministrationApi.ReadNodeProperties(nsxClient.Context)

	if err != nil || resp.StatusCode == http.StatusNotFound {
		return "", "", fmt.Errorf("Failed to retrieve NSX version (%s). Please check connectivity and authentication settings of the provider", err)

	}
	//log.Printf("Connected to NSXT Manager with version%s", nodeProperties.NodeVersion)
	return nodeProperties.Hostname, nodeProperties.NodeVersion, nil
}

//GetNSXVersion will get the NSX manager version
func GetNSXVersion(nsxClient *api.APIClient) (nsxVersion, nsxtHostname string, err error) {
	nsxtVersion, nsxtHostname, err := getNSXVersion(nsxClient)
	return nsxtVersion, nsxtHostname, err
}

//NsxtIPBlockCreate will create IP Block in IPAM under Advanced Networking
func NsxtIPBlockCreate(nsxClient *api.APIClient) (ipBlockID string, err error) {
	// nsxClient := m.(nsxtClients).NsxtClient
	// if nsxClient == nil {
	// 	return resourceNotSupportedError()
	// }

	// description := d.Get("description").(string)
	// displayName := d.Get("display_name").(string)
	// tags := getTagsFromSchema(d)
	// cidr := d.Get("cidr").(string)
	ipBlock := manager.IpBlock{
		Description: "Demo from Script",
		DisplayName: "GPU Server pool",
		//Tags:        tags,
		Cidr: "192.168.168.0/24",
	}
	// Create the IP Block
	ipBlock, resp, err := nsxClient.PoolManagementApi.CreateIpBlock(nsxClient.Context, ipBlock)

	if err != nil {
		return "", fmt.Errorf("Error during IpBlock create: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Unexpected status returned during IpBlock create: %v", resp.StatusCode)
	}
	//d.SetId(ipBlock.Id)

	return ipBlock.Id, err
}

//struct to store the token
type jwtToken struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

//get VMC on AWS API token
func getAPIToken(vmcAuthHost string, vmcAccessToken string) (string, error) {

	payload := strings.NewReader("refresh_token=" + vmcAccessToken)
	req, _ := http.NewRequest("POST", "https://"+vmcAuthHost, payload)

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return "", err
	}

	if res.StatusCode != 200 {
		b, _ := ioutil.ReadAll(res.Body)
		return "", fmt.Errorf("Unexpected status code %d trying to get auth token. %s", res.StatusCode, string(b))
	}

	defer res.Body.Close()
	token := jwtToken{}
	json.NewDecoder(res.Body).Decode(&token)

	return token.AccessToken, nil
}

//create TLS ocnfiguration with cert files
func getConnectorTLSConfig(insecure bool, clientCertFile string, clientKeyFile string, caFile string) (*tls.Config, error) {

	tlsConfig := tls.Config{InsecureSkipVerify: insecure}

	if len(clientCertFile) > 0 {

		if len(clientKeyFile) == 0 {
			return nil, fmt.Errorf("Please provide key file for client certificate")
		}

		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to load client cert/key pair: %v", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if len(caFile) > 0 {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.RootCAs = caCertPool
	}

	tlsConfig.BuildNameToCertificate()

	return &tlsConfig, nil
}

//take arguments from env varibale and configure connector
func configurePolicyConnectorData(clients *nsxtClients) error {
	hostIP := os.Getenv("NSXT_MANAGER_HOST")
	username := os.Getenv("NSXT_USERNAME")
	password := os.Getenv("NSXT_PASSWORD")
	insecure := true
	policyGlobalManager := false
	//clientAuthCertFile := os.Getenv("CLIENT_AUTH_CERT_FILE")
	//clientAuthKeyFile := os.Getenv("CLIENT_AUTH_KEY_FILE")
	//caFile := os.Getenv("CA_CERT_FILE")
	//policyEnforcementPoint := ""
	//vmcAccessToken := ""
	//vmcAuthHost := ""

	if hostIP == "" {
		return fmt.Errorf("host must be provided")
	}

	host := fmt.Sprintf("https://%s", hostIP)
	securityCtx := core.NewSecurityContextImpl()
	securityCtx.SetProperty(security.AUTHENTICATION_SCHEME_ID, security.USER_PASSWORD_SCHEME_ID)
	securityCtx.SetProperty(security.USER_KEY, username)
	securityCtx.SetProperty(security.PASSWORD_KEY, password)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		Proxy:           http.ProxyFromEnvironment,
	}

	httpClient := http.Client{Transport: tr}
	clients.PolicyHTTPClient = &httpClient
	clients.PolicySecurityContext = securityCtx
	clients.Host = host
	//clients.PolicyEnforcementPoint = policyEnforcementPoint
	//clients.PolicySite = policySite
	clients.PolicyGlobalManager = policyGlobalManager

	return nil
}

type remoteBasicAuthHeaderProcessor struct {
}

func newRemoteBasicAuthHeaderProcessor() *remoteBasicAuthHeaderProcessor {
	return &remoteBasicAuthHeaderProcessor{}
}

func (processor remoteBasicAuthHeaderProcessor) Process(req *http.Request) error {
	oldAuthHeader := req.Header.Get("Authorization")
	newAuthHeader := strings.Replace(oldAuthHeader, "Basic", "Remote", 1)
	req.Header.Set("Authorization", newAuthHeader)
	return nil
}

func initCommonConfig(cc *commonProviderConfig) commonProviderConfig {
	return commonProviderConfig{
		RemoteAuth:             false,
		ToleratePartialSuccess: false,
	}
}

//ProviderConfigure configures the provider NSXT API end point and NSXT REST connector
func ProviderConfigure() (interface{}, error) {
	commonConfig := commonProviderConfig{
		RemoteAuth:             false,
		ToleratePartialSuccess: true,
	}
	clients := nsxtClients{
		CommonConfig: commonConfig,
	}

	err := configureNsxtClient(&clients)
	if err != nil {
		return nil, err
	}

	err = configurePolicyConnectorData(&clients)
	if err != nil {
		return nil, err
	}

	return clients, nil
}

func getPolicyConnector(clients interface{}) *client.RestConnector {
	c := clients.(nsxtClients)
	connector := client.NewRestConnector(c.Host, *c.PolicyHTTPClient)
	if c.PolicySecurityContext != nil {
		connector.SetSecurityContext(c.PolicySecurityContext)
	}
	if c.CommonConfig.RemoteAuth {
		connector.AddRequestProcessor(newRemoteBasicAuthHeaderProcessor())
	}

	return connector
}

func getPolicyEnforcementPoint(clients interface{}) string {
	return clients.(nsxtClients).PolicyEnforcementPoint
}

func getPolicySite(clients interface{}) string {
	return clients.(nsxtClients).PolicySite
}

func isPolicyGlobalManager(clients interface{}) bool {
	return clients.(nsxtClients).PolicyGlobalManager
}

func getCommonProviderConfig(clients interface{}) commonProviderConfig {
	return clients.(nsxtClients).CommonConfig
}

func getGlobalPolicyEnforcementPointPath(m interface{}, sitePath *string) string {
	return fmt.Sprintf("%s/enforcement-points/%s", *sitePath, getPolicyEnforcementPoint(m))
}

func resourceNsxtPolicySegmentExists(id string, connector *client.RestConnector, isGlobalManager bool) bool {
	var err error

	if isGlobalManager {
		client := gm_infra.NewDefaultSegmentsClient(connector)
		_, err = client.Get(id)
	} else {
		client := infra.NewDefaultSegmentsClient(connector)
		_, err = client.Get(id)
	}
	if err == nil {
		return true
	}

	if isNotFoundError(err) {
		return false
	}

	logAPIError("Error retrieving Segment", err)
	return false
}

func policySegmentResourceToStruct(isVlan bool) (model.Segment, error) {
	// Read the rest of the configured parameters
	description := ""
	displayName := ""
	domainName := ""
	tzPath := ""
	//tags := getPolicyTagsFromSchema(d)
	//domainName := d.Get("domain_name").(string)
	//dhcpConfigPath := d.Get("dhcp_config_path").(string)
	//revision := int64(d.Get("revision").(int))
	obj := model.Segment{
		DisplayName: &displayName,
		//Tags:        tags,
		//Revision:    &revision,
	}

	if description != "" {
		obj.Description = &description
	}

	if domainName != "" {
		obj.DomainName = &domainName
	}

	if tzPath != "" {
		obj.TransportZonePath = &tzPath
	}

	// if dhcpConfigPath != "" && nsxVersionHigherOrEqual("3.0.0") {
	// 	obj.DhcpConfigPath = &dhcpConfigPath
	// }

	// var vlanIds []string
	// var subnets []interface{}
	// var subnetStructs []model.SegmentSubnet
	// if isVlan {
	// 	// VLAN specific fields
	// 	for _, vlanID := range vlanIds.([]interface{}) {
	// 		vlanIds = append(vlanIds, vlanID.(string))
	// 	}
	// 	obj.VlanIds = vlanIds
	// } else {
	// 	// overlay specific fields
	// 	connectivityPath := ""
	// 	overlayID, exists := [, false
	// 	if exists {
	// 		overlayID64 := int64(overlayID.(int))
	// 		obj.OverlayId = &overlayID64
	// 	}
	// 	if connectivityPath != "" {
	// 		obj.ConnectivityPath = &connectivityPath
	// 	}
	// }
	//	subnets = ""
	// if len(subnets) > 0 {
	// 	for _, subnet := range subnets {
	// 		subnetMap := subnet.(map[string]interface{})
	// 		dhcpRanges := subnetMap["dhcp_ranges"].([]interface{})
	// 		var dhcpRangeList []string
	// 		if len(dhcpRanges) > 0 {
	// 			for _, dhcpRange := range dhcpRanges {
	// 				dhcpRangeList = append(dhcpRangeList, dhcpRange.(string))
	// 			}
	// 		}
	// 		gwAddr := subnetMap["cidr"].(string)
	// 		network := subnetMap["network"].(string)
	// 		subnetStruct := model.SegmentSubnet{
	// 			DhcpRanges:     dhcpRangeList,
	// 			GatewayAddress: &gwAddr,
	// 			Network:        &network,
	// 		}
	// 		config, err := getSegmentSubnetDhcpConfigFromSchema(subnetMap)
	// 		if err != nil {
	// 			return obj, err
	// 		}

	// 		subnetStruct.DhcpConfig = config

	// 		subnetStructs = append(subnetStructs, subnetStruct)
	// 	}
	// }
	//obj.Subnets = subnetStructs

	// advConfig := d.Get("advanced_config").([]interface{})
	// if len(advConfig) > 0 {
	// 	advConfigMap := advConfig[0].(map[string]interface{})
	// 	connectivity := advConfigMap["connectivity"].(string)
	// 	hybrid := advConfigMap["hybrid"].(bool)
	// 	egress := advConfigMap["local_egress"].(bool)
	// 	var poolPaths []string
	// 	if advConfigMap["cidr"] != nil {
	// 		poolPaths = append(poolPaths, advConfigMap["cidr"].(string))
	// 	}
	// 	advConfigStruct := model.SegmentAdvancedConfig{
	// 		AddressPoolPaths: poolPaths,
	// 		Hybrid:           &hybrid,
	// 		LocalEgress:      &egress,
	// 	}

	// 	if connectivity != "" {
	// 		advConfigStruct.Connectivity = &connectivity
	// 	}

	// 	if nsxVersionHigherOrEqual("3.0.0") {
	// 		teamingPolicy := advConfigMap["uplink_teaming_policy"].(string)
	// 		if teamingPolicy != "" {
	// 			advConfigStruct.UplinkTeamingPolicyName = &teamingPolicy
	// 		}
	// 	}
	// 	obj.AdvancedConfig = &advConfigStruct
	// }

	//l2Ext := d.Get("l2_extension").([]interface{})
	// if len(l2Ext) > 0 {
	// 	l2ExtMap := l2Ext[0].(map[string]interface{})
	// 	vpnPaths := interfaceListToStringList(l2ExtMap["l2vpn_paths"].([]interface{}))
	// 	tunnelID := int64(l2ExtMap["tunnel_id"].(int))
	// 	l2Struct := model.L2Extension{
	// 		L2vpnPaths: vpnPaths,
	// 		TunnelId:   &tunnelID,
	// 	}
	// 	obj.L2Extension = &l2Struct
	// }

	return obj, nil
}

//CreateNSXTPolicySegment will create segment
// func CreateNSXTPolicySegment(connector *client.RestConnector, isVlan bool) error {
// 	//connector := getPolicyConnector(m)

// 	id := newUUID()
// 	// Initialize resource Id and verify this ID is not yet used
// 	// id, err := getOrGenerateID(connector, resourceNsxtPolicySegmentExists)
// 	// if err != nil {
// 	// 	return err
// 	// }

// 	// Create the resource using PATCH
// 	log.Printf("Creating Segment with ID %s", id)
// 	obj, err := policySegmentResourceToStruct(isVlan)
// 	if err != nil {
// 		return err
// 	}
// 	// if isPolicyGlobalManager(false) {
// 	// 	gmObj, err := convertModelBindingType(obj, model.SegmentBindingType(), gm_model.SegmentBindingType())
// 	// 	if err != nil {
// 	// 		return err
// 	// 	}
// 	// 	client := gm_infra.NewDefaultSegmentsClient(connector)
// 	// 	err = client.Patch(id, gmObj.(gm_model.Segment))
// 	// } else {
// 	client := infra.NewDefaultSegmentsClient(connector)
// 	err = client.Patch(id, obj)
// 	//}
// 	if err != nil {
// 		return handleCreateError("Segment", id, err)
// 	}
// 	//d.SetId(id)
// 	//d.Set("nsx_id", id)
// 	fmt.Println("Segment ID:", id)
// 	return nil // nsxtPolicySegmentRead(d, m, isVlan)
// }

//NSXTPolicySegmentRead will retrieve NSXT segment with supplied ID
func NSXTPolicySegmentRead(id string, m interface{}, isVlan bool) error {
	connector := getPolicyConnector(m)

	//id := d.Id()
	if id == "" {
		return fmt.Errorf("Please provide Segment ID")
	}

	var obj model.Segment

	if isPolicyGlobalManager(m) {
		client := gm_infra.NewDefaultSegmentsClient(connector)
		gmObj, err := client.Get(id)
		if err != nil {
			return handleReadError("Segment", id, err)
		}
		lmObj, err := convertModelBindingType(gmObj, gm_model.SegmentBindingType(), model.SegmentBindingType())
		if err != nil {
			return err
		}
		obj = lmObj.(model.Segment)
	} else {
		client := infra.NewDefaultSegmentsClient(connector)
		var err error
		obj, err = client.Get(id)
		if err != nil {
			return handleReadError("Segment", id, err)
		}
	}

	//d.Set("display_name", obj.DisplayName)
	//d.Set("description", obj.Description)
	//setPolicyTagsInSchema(d, obj.Tags)
	//d.Set("nsx_id", id)
	//d.Set("path", obj.Path)
	//d.Set("revision", obj.Revision)
	//d.Set("connectivity_path", obj.ConnectivityPath)
	//d.Set("dhcp_config_path", obj.DhcpConfigPath)
	//d.Set("domain_name", obj.DomainName)
	//d.Set("transport_zone_path", obj.TransportZonePath)

	// if isVlan {
	// 	d.Set("vlan_ids", obj.VlanIds)
	// } else {
	// 	if obj.OverlayId != nil {
	// 		d.Set("overlay_id", int(*obj.OverlayId))
	// 	} else {
	// 		d.Set("overlay_id", "")
	// 	}
	// }

	// if obj.AdvancedConfig != nil {
	// 	advConfig := make(map[string]interface{})
	// 	poolPaths := obj.AdvancedConfig.AddressPoolPaths
	// 	if len(poolPaths) > 0 {
	// 		advConfig["address_pool_path"] = poolPaths[0]
	// 	}
	// 	advConfig["connectivity"] = obj.AdvancedConfig.Connectivity
	// 	advConfig["hybrid"] = obj.AdvancedConfig.Hybrid
	// 	advConfig["local_egress"] = obj.AdvancedConfig.LocalEgress
	// 	if obj.AdvancedConfig.UplinkTeamingPolicyName != nil {
	// 		advConfig["uplink_teaming_policy"] = *obj.AdvancedConfig.UplinkTeamingPolicyName
	// 	}
	// 	// This is a list with 1 element
	// 	var advConfigList []map[string]interface{}
	// 	advConfigList = append(advConfigList, advConfig)
	// 	//d.Set("advanced_config", advConfigList)
	// }

	// if obj.L2Extension != nil {
	// 	l2Ext := make(map[string]interface{})
	// 	l2Ext["l2vpn_paths"] = obj.L2Extension.L2vpnPaths
	// 	l2Ext["tunnel_id"] = obj.L2Extension.TunnelId
	// 	// This is a list with 1 element
	// 	var l2ExtList []map[string]interface{}
	// 	l2ExtList = append(l2ExtList, l2Ext)
	// 	//d.Set("l2_extension", l2ExtList)
	// }

	// var subnetSegments []interface{}
	// for _, subnetSeg := range obj.Subnets {
	// 	seg := make(map[string]interface{})
	// 	seg["dhcp_ranges"] = subnetSeg.DhcpRanges
	// 	seg["cidr"] = subnetSeg.GatewayAddress
	// 	seg["network"] = subnetSeg.Network
	// 	setSegmentSubnetDhcpConfigInSchema(seg, subnetSeg)
	// 	subnetSegments = append(subnetSegments, seg)
	// }

	//d.Set("subnet", subnetSegments)
	//fmt.Sprintf(*obj.Id)
	d, err := json.Marshal(obj)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(d))
	return nil
}

//NSXTPolicySegmentCreate create new policy segment
func NSXTPolicySegmentCreate(m interface{}, isVlan bool) error {
	connector := getPolicyConnector(m)
	// Initialize resource Id and verify this ID is not yet used
	id := newUUID() //"1d6afaec-4b33-4840-9df2-3495851b9a33"

	isGlobalManager := isPolicyGlobalManager(m)

	isSegmentIDExists := resourceNsxtPolicySegmentExists(id, connector, isGlobalManager)

	if isSegmentIDExists {
		return fmt.Errorf("Resource with id %s already exists", id)

	}
	// Create the resource using PATCH
	fmt.Printf("Creating Segment with ID %s", id)
	obj, err := policySegmentResourceToStruct(isVlan)
	if err != nil {
		return err
	}

	if isGlobalManager {
		gmObj, convErr := convertModelBindingType(obj, model.SegmentBindingType(), gm_model.SegmentBindingType())
		if convErr != nil {
			return convErr
		}
		client := gm_infra.NewDefaultSegmentsClient(connector)
		err = client.Patch(id, gmObj.(gm_model.Segment))
	} else {
		client := infra.NewDefaultSegmentsClient(connector)
		err = client.Patch(id, obj)
	}
	if err != nil {
		return handleCreateError("Segment", id, err)
	}
	fmt.Printf("Segment with ID %s created ", id)

	return err //NSXTPolicySegmentRead(id, m, isVlan)
}

//GetPolicyConnector will return the REST Connector
// func GetPolicyConnector() (*client.RestConnector, error) {
// 	if os.Getenv("NSXT_MANAGER_HOST") == "" {
// 		return nil, fmt.Errorf("NSXT_MANAGER_HOST is not set in environment")
// 	}

// 	// Try to create a temporary client using the tests configuration
// 	// This is necessary since the test PreCheck is called before the client is initialized.
// 	insecure := true
// 	if v := strings.ToLower(os.Getenv("NSXT_ALLOW_UNVERIFIED_SSL")); v != "false" && v != "0" {
// 		insecure = true
// 	}

// 	hostIP := os.Getenv("NSXT_MANAGER_HOST")
// 	host := fmt.Sprintf("https://%s", hostIP)
// 	username := os.Getenv("NSXT_USERNAME")
// 	password := os.Getenv("NSXT_PASSWORD")

// 	//TODO: add error handling
// 	securityCtx := core.NewSecurityContextImpl()
// 	securityCtx.SetProperty(security.AUTHENTICATION_SCHEME_ID, security.USER_PASSWORD_SCHEME_ID)
// 	securityCtx.SetProperty(security.USER_KEY, username)
// 	securityCtx.SetProperty(security.PASSWORD_KEY, password)

// 	tr := &http.Transport{
// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
// 		Proxy:           http.ProxyFromEnvironment,
// 	}
// 	httpClient := http.Client{Transport: tr}
// 	connector := client.NewRestConnector(host, httpClient)
// 	connector.SetSecurityContext(securityCtx)

// 	return connector, nil
// }
