/* Copyright © 2019 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: MPL-2.0 */

package controller

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/vmware/vsphere-automation-sdk-go/runtime/bindings"
)

// Default names or prefixed of NSX backend existing objects used in the acceptance tests.
// Those defaults can be overridden using environment parameters
const tier0RouterDefaultName string = "PLR-1 LogicalRouterTier0"
const edgeClusterDefaultName string = "edgecluster1"
const vlanTransportZoneName string = "transportzone2"
const overlayTransportZoneNamePrefix string = "1-transportzone"
const macPoolDefaultName string = "DefaultMacPool"

func newUUID() string {
	uuid, _ := uuid.NewRandom()
	return uuid.String()
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// func getOrGenerateID(d *schema.ResourceData, m interface{}, presenceChecker func(string, *client.RestConnector, bool) bool) (string, error) {
// 	connector := getPolicyConnector(m)
// 	isGlobalManager := isPolicyGlobalManager(m)

// 	id := d.Get("nsx_id").(string)
// 	if id == "" {
// 		return newUUID(), nil
// 	}

// 	if presenceChecker(id, connector, isGlobalManager) {
// 		return "", fmt.Errorf("Resource with id %s already exists", id)
// 	}

// 	return id, nil
// }

func getVlanTransportZoneName() string {
	name := os.Getenv("NSXT_TEST_VLAN_TRANSPORT_ZONE")
	if name == "" {
		name = vlanTransportZoneName
	}
	return name
}

func getMacPoolName() string {
	name := os.Getenv("NSXT_TEST_MAC_POOL")
	if name == "" {
		name = macPoolDefaultName
	}
	return name
}

func getIPPoolName() string {
	return os.Getenv("NSXT_TEST_IP_POOL")
}

func getTestVMID() string {
	return os.Getenv("NSXT_TEST_VM_ID")
}

func getTestVMName() string {
	return os.Getenv("NSXT_TEST_VM_NAME")
}

func getTestSiteName() string {
	return os.Getenv("NSXT_TEST_SITE_NAME")
}

func getTestAnotherSiteName() string {
	return os.Getenv("NSXT_TEST_ANOTHER_SITE_NAME")
}

func getTestCertificateName(isClient bool) string {
	if isClient {
		return os.Getenv("NSXT_TEST_CLIENT_CERTIFICATE_NAME")
	}
	return os.Getenv("NSXT_TEST_CERTIFICATE_NAME")
}

//GetObjIDByName will retrieve the objects
// func GetObjIDByName(objName string, resourceType string) (string, error) {
// 	connector, err1 := GetPolicyConnector()
// 	if err1 != nil {
// 		return "", fmt.Errorf("Error during test client initialization: %v", err1)
// 	}

// 	resultValues, err2 := listPolicyResourcesByType(connector, &resourceType, nil)
// 	if err2 != nil {
// 		return "", err2
// 	}

// 	converter := bindings.NewTypeConverter()

// 	converter.SetMode(bindings.REST)

// 	for _, result := range resultValues {
// 		dataValue, errors := converter.ConvertToGolang(result, model.PolicyResourceBindingType())
// 		if len(errors) > 0 {
// 			return "", errors[0]
// 		}
// 		policyResource := dataValue.(model.PolicyResource)

// 		if *policyResource.DisplayName == objName {
// 			return *policyResource.Id, nil
// 		}
// 	}

// 	return "", fmt.Errorf("%s with name '%s' was not found", resourceType, objName)
// }

// func getCustomizedPolicyTagsFromSchema(d *schema.ResourceData, schemaName string) []model.Tag {
// 	tags := d.Get(schemaName).(*schema.Set).List()
// 	var tagList []model.Tag
// 	for _, tag := range tags {
// 		data := tag.(map[string]interface{})
// 		tagScope := data["scope"].(string)
// 		tagTag := data["tag"].(string)
// 		elem := model.Tag{
// 			Scope: &tagScope,
// 			Tag:   &tagTag}

// 		tagList = append(tagList, elem)
// 	}
// 	return tagList
// }

// func setCustomizedPolicyTagsInSchema(d *schema.ResourceData, tags []model.Tag, schemaName string) error {
// 	var tagList []map[string]interface{}
// 	for _, tag := range tags {
// 		elem := make(map[string]interface{})
// 		elem["scope"] = tag.Scope
// 		elem["tag"] = tag.Tag
// 		tagList = append(tagList, elem)
// 	}
// 	err := d.Set(schemaName, tagList)
// 	return err
// }

// func getPolicyTagsFromSchema(d *schema.ResourceData) []model.Tag {
// 	return getCustomizedPolicyTagsFromSchema(d, "tag")
// }

// func setPolicyTagsInSchema(d *schema.ResourceData, tags []model.Tag) error {
// 	return setCustomizedPolicyTagsInSchema(d, tags, "tag")
// }

// func getPathListFromMap(data map[string]interface{}, attrName string) []string {
// 	pathList := interface2StringList(data[attrName].(*schema.Set).List())
// 	if len(pathList) == 0 {
// 		// Convert empty value to "ANY"
// 		pathList = append(pathList, "ANY")
// 	}

// 	return pathList
// }

func setPathListInMap(data map[string]interface{}, attrName string, pathList []string) {
	if len(pathList) == 1 && pathList[0] == "ANY" {
		data[attrName] = nil
	} else {
		data[attrName] = pathList
	}
}

func getDomainFromResourcePath(rPath string) string {
	return getResourceIDFromResourcePath(rPath, "domains")
}

func getResourceIDFromResourcePath(rPath string, rType string) string {
	segments := strings.Split(rPath, "/")
	for i, seg := range segments {
		if seg == rType && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return ""
}

// func nsxtDomainResourceImporter(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
// 	importDomain := defaultDomain
// 	importID := d.Id()
// 	s := strings.Split(importID, "/")
// 	if len(s) == 2 {
// 		importDomain = s[0]
// 		d.SetId(s[1])
// 	} else {
// 		d.SetId(s[0])
// 	}

// 	d.Set("domain", importDomain)

// 	return []*schema.ResourceData{d}, nil
// }

func isPolicyPath(policyPath string) bool {
	pathSegs := strings.Split(policyPath, "/")
	if len(pathSegs) < 4 {
		return false
	} else if pathSegs[0] != "" || pathSegs[len(pathSegs)-1] == "" {
		return false
	} else if !strings.Contains(pathSegs[1], "infra") {
		// must be infra or global-infra as of now
		return false
	}
	return true
}

func getPolicyIDFromPath(path string) string {
	tokens := strings.Split(path, "/")
	return tokens[len(tokens)-1]
}

func interfaceListToStringList(interfaces []interface{}) []string {
	var strList []string
	for _, elem := range interfaces {
		strList = append(strList, elem.(string))
	}
	return strList
}

func policyResourceNotSupportedError() error {
	return fmt.Errorf("This NSX policy resource is not supported with given provider settings")
}

func collectSeparatedStringListToMap(stringList []string, separator string) map[string]string {
	var strMap map[string]string
	strMap = make(map[string]string)
	for _, elem := range stringList {
		segs := strings.Split(elem, separator)
		if len(segs) > 1 {
			strMap[segs[0]] = segs[1]
		}

	}
	return strMap
}

func stringListToCommaSeparatedString(stringList []string) string {
	var str string
	if len(stringList) > 0 {
		for i, seg := range stringList {
			str += seg
			if i < len(stringList)-1 {
				str += ","
			}
		}
	}
	return str
}

func commaSeparatedStringToStringList(commaString string) []string {
	var strList []string
	for _, seg := range strings.Split(commaString, ",") {
		if seg != "" {
			strList = append(strList, seg)
		}
	}
	return strList
}

// func nsxtPolicyWaitForRealizationStateConf(connector *client.RestConnector, d *schema.ResourceData, realizedEntityPath string) *resource.StateChangeConf {
// 	client := realized_state.NewDefaultRealizedEntitiesClient(connector)
// 	pendingStates := []string{"UNKNOWN", "UNREALIZED"}
// 	targetStates := []string{"REALIZED", "ERROR"}
// 	stateConf := &resource.StateChangeConf{
// 		Pending: pendingStates,
// 		Target:  targetStates,
// 		Refresh: func() (interface{}, string, error) {

// 			realizationResult, realizationError := client.List(realizedEntityPath, &policySite)
// 			if realizationError == nil {
// 				// Find the right entry
// 				for _, objInList := range realizationResult.Results {
// 					if objInList.State != nil {
// 						return objInList, *objInList.State, nil
// 					}
// 				}
// 				// Realization info not found yet
// 				return nil, "UNKNOWN", nil
// 			}
// 			return nil, "", realizationError
// 		},
// 		Timeout:    d.Timeout(schema.TimeoutCreate),
// 		MinTimeout: 1 * time.Second,
// 		Delay:      1 * time.Second,
// 	}

// 	return stateConf
// }

func getPolicyEnforcementPointPath(m interface{}) string {
	return "/infra/sites/default/enforcement-points/" + getPolicyEnforcementPoint(m)
}

func convertModelBindingType(obj interface{}, sourceType bindings.BindingType, destType bindings.BindingType) (interface{}, error) {
	converter := bindings.NewTypeConverter()
	converter.SetMode(bindings.REST)
	dataValue, err := converter.ConvertToVapi(obj, sourceType)
	if err != nil {
		return nil, err[0]
	}

	gmObj, err := converter.ConvertToGolang(dataValue, destType)
	if err != nil {
		return nil, err[0]
	}

	return gmObj, nil
}
