package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
)

func get_ips() []string {
	var ips []string
	file, err := os.Open("ip.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips = append(ips, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	return ips
}

// all the useful content within the json.
type GeneralReturn struct {
	Whois         string `json:"whois"`
	Reputation    int    `json:"reputation"`
	Indicator     string `json:"indicator"`
	TypeTitle     string `json:"type_title"`
	BaseIndicator struct {
	} `json:"base_indicator"`
	PulseInfo struct {
		Count      int           `json:"count"`
		Pulses     []interface{} `json:"pulses"`
		References []interface{} `json:"references"`
		Related    struct {
			Alienvault struct {
				Adversary       []interface{} `json:"adversary"`
				MalwareFamilies []interface{} `json:"malware_families"`
				Industries      []interface{} `json:"industries"`
			} `json:"alienvault"`
			Other struct {
				Adversary       []interface{} `json:"adversary"`
				MalwareFamilies []interface{} `json:"malware_families"`
				Industries      []interface{} `json:"industries"`
			} `json:"other"`
		} `json:"related"`
	} `json:"pulse_info"`
	FalsePositive []interface{} `json:"false_positive"`
	Validation    []struct {
		Source  string `json:"source"`
		Message string `json:"message"`
		Name    string `json:"name"`
	} `json:"validation"`
	Asn         string `json:"asn"`
	CityData    bool   `json:"city_data"`
	City        string `json:"city"`
	Region      string `json:"region"`
	CountryName string `json:"country_name"`
}

func otx_search(ips string) {
	url := "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ips + "/general"
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	var general_return GeneralReturn
	json.Unmarshal(body, &general_return)
	fmt.Printf("OTX.ALIENVAULT.COM\n")
	// Adjust these print statements to add anything extra you want, or remove anything you don't want. Personally this information is already enough for my purposes.
	fmt.Printf("IP: %v \nPulse Count: %d \nASN: %s \n", ips, general_return.PulseInfo.Count, general_return.Asn)
	fmt.Printf("City: %s \nRegion: %s \nCountry: %s \n", general_return.City, general_return.Region, general_return.CountryName)
	fmt.Printf("Validation: %s \n\n", general_return.Validation)

	file, err := os.OpenFile("OTXResults.csv", os.O_APPEND|os.O_WRONLY, 0600)
	file.WriteString(ips + "," + strconv.Itoa(general_return.PulseInfo.Count) + "," + general_return.Asn + "," + general_return.City + "," + general_return.Region + "," + general_return.CountryName + "\n")

}

func main() {
	fmt.Printf("█▀█ ▀█▀ ▀▄▀   █▀ █▀▀ ▄▀█ █▀█ █▀▀ █░█\n█▄█ ░█░ █░█   ▄█ ██▄ █▀█ █▀▄ █▄▄ █▀█\n\n\n")
	file, err := os.Create("OTXResults.csv")
	file.WriteString("IP,Pulse Count,ASN,City,Region,Country\n")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	ips := get_ips()
	for _, ip := range ips {
		otx_search(ip)
	}
}
