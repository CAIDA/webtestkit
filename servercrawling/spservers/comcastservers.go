package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
)

const ComcastTestplanUrl = "https://speedtestprod.mw.comcast.net/api/testplans"
const ComcastServerSelect = "https://speedtestprod.mw.comcast.net/api/selectservers/%s"

type ComcastTestplan struct {
	ServerLocation []string `json:"serverLocation"`
}

type ComcastServer struct {
	IPv4 string `json:"IPv4Address"`
	IPv6 string `json:"IPv6Address"`
	Name string `json:"Sitename"`
	Host string `json:"Fqdn"`
	Id   int    `json:"ServerId"`
}

type ComcastConfig struct {
	CreateFile string
	OpenFile   string
	Retry      int
	PrintList  string
}

var wg sync.WaitGroup
var allserver []ComcastServer
var retry int

func main() {
	cfg := &ComcastConfig{}
	flag.StringVar(&cfg.CreateFile, "n", "comcast.json", "Crawl and create JSON file")
	flag.StringVar(&cfg.OpenFile, "o", "", "Read existing json datafile")
	flag.IntVar(&cfg.Retry, "r", 10, "Number of retry for each site to enumerate all servers")
	flag.StringVar(&cfg.PrintList, "p", "comcast.ip.txt", "Print newline seperated IPv4 address")
	flag.Parse()
	if len(cfg.OpenFile) > 0 {
		//read and fill allserver
		jsonFile, err := os.Open(cfg.OpenFile)
		if err != nil {
			log.Fatal(err)
		}
		defer jsonFile.Close()
		bvalue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(bvalue, &allserver)
	} else {
		retry = cfg.Retry
		testplan := LoadTestPlan()
		chan_server := make(chan ComcastServer)
		go ResultCollector(chan_server)
		for _, location := range testplan.ServerLocation {
			log.Println("Loading location", location)
			wg.Add(1)
			go LoadServers(location, chan_server)
		}
		wg.Wait()
		close(chan_server)

		file, _ := json.MarshalIndent(allserver, "", " ")
		_ = ioutil.WriteFile(cfg.CreateFile, file, 0644)
		log.Println("Crawled", len(allserver))
	}
	fip, err := os.Create(cfg.PrintList)
	defer fip.Close()
	if err != nil {
		log.Fatal(err)
	}
	for _, server := range allserver {
		_, err := fip.WriteString(server.IPv4 + "\n")
		if err != nil {
			log.Fatal(err)
		}
	}
	fip.Sync()
}

func LoadTestPlan() *ComcastTestplan {
	response, err := http.Get(ComcastTestplanUrl)
	if err != nil {
		log.Fatal(err)
	}
	respData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	testplan := &ComcastTestplan{}
	json.Unmarshal(respData, testplan)
	return testplan
}

func LoadServers(site string, c_server chan ComcastServer) {
	qstring := fmt.Sprintf(ComcastServerSelect, site)
	for i := 0; i < retry; i++ {
		response, err := http.Get(qstring)
		if err != nil {
			log.Fatal(err)
		}
		respData, err := ioutil.ReadAll(response.Body)
		cs := []ComcastServer{}
		json.Unmarshal(respData, &cs)
		if len(cs) == 1 {
			c_server <- cs[0]
		}
	}
	wg.Done()
}

func ResultCollector(c_server chan ComcastServer) {
	smap := make(map[int]bool)
	for s := range c_server {
		if _, sexist := smap[s.Id]; !sexist {
			smap[s.Id] = true
			allserver = append(allserver, s)
		}
	}
}
