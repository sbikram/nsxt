package controller

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

//GetSegments will retrieve segments
func GetSegments() {
	// Create a Resty Client
	// client := resty.New()
	// auth := basicAuth("admin", "VMware1!VMware1!")
	// resp, err := client.R().
	// 	SetHeader("Accept", "application/json").
	// 	SetHeader("Authorization", fmt.Sprintf("Basic %s", auth)).
	// 	Get("https://192.168.5.10/policy/api/v1/infra/segments/")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(resp.String())
	url := "https://192.168.5.10/policy/api/v1/infra/segments/"
	//POST
	//req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	//GET
	req, err := http.NewRequest("GET", url, nil)
	//fmt.Println("req:>", req)

	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(os.Getenv("NSXT_USERNAME"), os.Getenv("NSXT_PASSWORD"))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	//client := &http.Client{}
	resp, err := client.Do(req)
	//fmt.Println("resp:>", resp)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
}
