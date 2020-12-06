/* Copyright © 2019 VMware, Inc. All Rights Reserved.
SPDX-License-Identifier: MPL-2.0 */

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/sbikram/nsxt/controller"
	api "github.com/vmware/go-vmware-nsxt"
	nsxt "github.com/vmware/go-vmware-nsxt"
)

//USAGE Program usage statement
//const USAGE string = "Usage: nsxcfg -h <nsx_host> -t <tcp_port> -u <username> -p <password> -c <certificate> -f <input_rv_tools.xlsx>"
const USAGE string = "Usage: nsxcfg -f <input_rv_tools.xlsx>"

func empty(str string) bool {
	return len(str) == 0
}

func validateCredentials() {
	var requiredVariables = []string{"NSXT_USERNAME", "NSXT_PASSWORD", "NSXT_MANAGER_HOST" /*"NSXT_ALLOW_UNVERIFIED_SSL"*/}
	for _, element := range requiredVariables {
		if v := os.Getenv(element); v == "" {
			str := fmt.Sprintf("Error: %s env varible is not set.", element)
			info := fmt.Sprintf("\nHelp: %s %s %s env varibles must be set.", requiredVariables[0], requiredVariables[1], requiredVariables[2])
			log.Fatal(str, info)
		}
	}
}

//GetNSXClient authenticated with NSX Manager
func GetNSXClient() (*api.APIClient, error) {
	validateCredentials()
	//Grab NSX credentials and RV tools file from commandline
	// nsxHost := flag.String("h", "", "NXS Manager IP")
	// nsxPort := flag.String("t", "", "NSX TCP Port")
	// nsxUser := flag.String("u", "", "NSX Username")
	// nsxPassword := flag.String("p", "", "NSX Password")
	// nsxCert := flag.String("c", "", "NSX Certificate")
	//rvToolsFile := flag.String("f", "", "Input RV Tools")
	//insecure := flag.String("i", "", "Allow Self Signed SSL Certificates")
	//create a NSX client using the  configuration

	//caFile := d.Get("ca_file").(string)

	maxRetries := 2
	retryMinDelay := 1
	retryMaxDelay := 1

	retriesConfig := nsxt.ClientRetriesConfiguration{
		MaxRetries:    maxRetries,
		RetryMinDelay: retryMinDelay, // milliseconds
		RetryMaxDelay: retryMaxDelay, // milliseconds
		//RetryOnStatuses: retryStatuses,
	}
	insecure := false
	if v := strings.ToLower(os.Getenv("NSXT_ALLOW_UNVERIFIED_SSL")); v != "false" && v != "0" {
		insecure = true
	}

	// if empty(*nsxHost) || empty(*nsxCert) || empty(*nsxUser) || empty(*nsxPassword) || empty(*nsxPort) {
	// 	fmt.Println(USAGE)
	// 	log.Fatalln("NSX Manager credentials cannot be empty")
	// }

	cfg := api.Configuration{
		BasePath:             "/api/v1",
		Host:                 os.Getenv("NSXT_MANAGER_HOST"),
		Scheme:               "https",
		UserName:             os.Getenv("NSXT_USERNAME"),
		Password:             os.Getenv("NSXT_PASSWORD"),
		UserAgent:            "itp-nsxt-configurator/1.0",
		RemoteAuth:           false,
		Insecure:             insecure,
		RetriesConfiguration: retriesConfig,
		//CAFile:               caFile,
		//ClientAuthCertFile:   clientAuthCertFile,
		//ClientAuthKeyFile:    clientAuthKeyFile,
	}
	//fmt.Println(cfg)
	return api.NewAPIClient(&cfg)
}

func main() {
	rvToolsFile := flag.String("f", "", "Input RV Tools")
	flag.Parse()
	if empty(*rvToolsFile) {
		fmt.Println(USAGE)
		log.Fatalln("No RV_Tools file found...")
	}

	fmt.Println("Authenticating with NSX Manager")

	// client, err := GetNSXClient()
	// if err != nil {
	// 	log.Fatalf("Error: %s ", err)
	// }

	// clients, err := controller.ProviderConfigure()
	// if err != nil {
	// 	fmt.Println("Error: Please check connectivity or authentication settings")
	// 	return
	// }

	//connector, err := controller.GetPolicyConnector()
	// if err != nil {
	// 	log.Fatal("Error: %s ", err)
	// }

	// nsxtHostname, nsxVerion, err := controller.GetNSXVersion(client)
	// if err != nil {
	// 	fmt.Println("Error: Please check connectivity or authentication settings")
	// 	return
	// }

	//fmt.Println("Authentication Successful\nConnected to NSXT Manager:", nsxtHostname)
	//fmt.Println("NSXT Manager Version:", nsxVerion)

	// err1 := controller.NSXTPolicySegmentRead("1d6afaec-4b33-4840-9df2-3495851b9a33", clients, false)
	// if err1 != nil {
	// 	log.Fatalf("Error: %s ", err)
	// }

	// err2 := controller.NSXTPolicySegmentCreate(clients, false)
	// if err2 != nil {
	// 	log.Fatalf("Error: %s ", err2)
	// }

	// e := controller.CreateNSXTPolicySegment(connector, false)
	// if e != nil {
	// 	log.Fatal("Error: %s ", err)
	// }

	// ipBlock, err := controller.NsxtIPBlockCreate(client)
	// if err != nil {
	// 	println(err.Error())
	// 	return
	// }
	//fmt.Println("IP Block Created:", ipBlock)
	controller.GetSegments()

	f, err := excelize.OpenFile(*rvToolsFile)

	if err != nil {
		println(err.Error())
		return
	}

	portGroups := []string{}
	vlans := []string{}
	rows, err := f.Rows(os.Getenv("RVTOOLS_SHEET_NAME"))
	if err != nil {
		fmt.Println(err)
		return
	}

	for rows.Next() {
		row := rows.Columns()
		// if err != nil {
		// 	fmt.Println(err)
		// 	return
		// }
		portGroups = append(portGroups, row[0])
		vlans = append(vlans, row[4])
		//fmt.Printf("%s\t%s\n", row[0], row[4]) // Print values in columns B and D
	}

	fmt.Println(portGroups[1:])
	fmt.Println(vlans[1:])
	//fmt.Println("Data reading complete")

}

//Alternate option to print columns if the range is known
// n := 40
// for i := 2; i < n; i++ {
// 	b, err := f.GetCellValue("BIKRAM", fmt.Sprintf("A%d", i))
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	d, err := f.GetCellValue("BIKRAM", fmt.Sprintf("E%d", i))
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	fmt.Printf("%s\t%s\n", b, d) // Print values in columns B and D
// }
// for _, col := range cols[0:1][0:] {
// 	for _, colCell := range col {
// 		portGroups = append(portGroups, colCell)

// 		//fmt.Println(colCell, "\t")
// 	}
// 	//fmt.Println()
// }
