package ookla

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"serverlinks/iputils"
	"spservers/common"
	"spservers/spdb"
	"strconv"
	"sync"
	"time"
)

type OoklaServer struct {
	Url         string `json:"url"`
	Lat         string `json:"lat"`
	Lon         string `json:"lon"`
	Name        string `json:"name"`
	Country     string `json:"country"`
	CountryCode string `json:"cc"`
	Sponsor     string `json:"sponsor"`
	Id          string `json:"id"`
	Https       int    `json:"https_functional"`
	Host        string `json:"host"`
	IPv4        string `json:"ipv4"`
	ASN         string `json:"asn"`
}

type ResultsCarrier struct {
	Hint    string
	Servers []OoklaServer
}

const OoklaQuery = "https://www.speedtest.net/api/js/servers?engine=js&search=%s&https_functional=true&limit=1000"
const MaxRecord = 100

var wg sync.WaitGroup
var allservers []OoklaServer
var hintsmap map[int][]string

func ConvOoklatoDB(oservers []OoklaServer, cfg *common.Config) []spdb.SpeedServer {
	ss := make([]spdb.SpeedServer, 0)
	for _, s := range oservers {
		ooklainfo := spdb.OoklaInfo{CountryCode: s.Country, Sponsor: s.Sponsor, Https: s.Https, Url: s.Url}
		longfloat, _ := strconv.ParseFloat(s.Lon, 64)
		latfloat, _ := strconv.ParseFloat(s.Lat, 64)
		location := spdb.JSONPoint{Type: "Point", Coord: []float64{longfloat, latfloat}}
		server := spdb.SpeedServer{Type: "ookla", Id: s.Id, Identifier: s.Name + " - " + s.Sponsor, City: s.Name, Country: s.CountryCode, Host: s.Host, IPv4: s.IPv4, IPv6: "", Asnv4: s.ASN, Enabled: true, Additional: &ooklainfo, Location: location, LastUpdated: cfg.StartTime}
		ss = append(ss, server)
	}
	return ss
}

func ImportOoklaServerfromFile(cfg *common.Config, filename string) []spdb.SpeedServer {
	var allokserver []OoklaServer
	jsonFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	serverstr, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(serverstr, &allokserver)
	return ConvOoklatoDB(allokserver, cfg)
}

func LoadOokla(cfg *common.Config) []spdb.SpeedServer {
	//	ip, asn := ResolveNet("okc-speedtest.onenet.net.prod.hosts.ooklaserver.net:8080")
	//	fmt.Println(ip, asn)
	/*	cfg = &Config{}
		flag.StringVar(&cfg.ReadFile, "o", "", "Read data from JSON file")
		flag.StringVar(&cfg.CreateFile, "n", "", "Crawl and create JSON file")
		flag.IntVar(&cfg.Workers, "w", 10, "Number of workers")
		flag.StringVar(&cfg.SearchASN, "asn", "", "Print servers in ASN")
		flag.StringVar(&cfg.SearchProvider, "isp", "", "Print servers in ISP")
		flag.StringVar(&cfg.SearchCountry, "country", "", "Print servers in country")
		flag.StringVar(&cfg.PrintList, "p", "", "Print IP of servers to file")
		flag.Parse()
	*/
	if cfg == nil {
		log.Fatal("Ookla config nil")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}
	/*if len(cfg.ReadFile) > 0 {
		jsonFile, err := os.Open(cfg.ReadFile)
		if err != nil {
			log.Fatal(err)
		}
		defer jsonFile.Close()
		bvalue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(bvalue, &allservers)
	} else
	*/
	filename := "ookla_" + strconv.FormatInt(cfg.StartTime.Unix(), 10) + ".json"
	if len(cfg.CreateFilePrefix) > 0 {
		filename = filepath.Join(cfg.CreateFilePrefix, filename)
	}
	log.Println("Load Ookla", filename)
	iphandler := iputils.NewIPHandler()
	hintsmap = make(map[int][]string)
	inithintlength := 2
	maxhintlength := 6
	hintsmap[inithintlength] = GenerateHints("", inithintlength)
	allservers = make([]OoklaServer, 0)
	rchan := make(chan ResultsCarrier)
	workerchan := make(chan int, cfg.Workers)
	go ResultCollector(rchan)
	for h := inithintlength; h <= maxhintlength; h++ {
		if allhints, hexist := hintsmap[h]; hexist && len(allhints) > 0 {
			log.Println("Hint round:", h, len(allhints))
			for i := 1; i <= len(allhints); i++ {
				wg.Add(1)
				go QueryServers(allhints[i-1], rchan, workerchan)
				workerchan <- 1
			}
			wg.Wait()
		}
	}
	close(rchan)
	//resolve all IP and Asn
	for oidx, _ := range allservers {
		wg.Add(1)
		go ResolveIP(oidx, iphandler, workerchan)
		workerchan <- 1
	}
	wg.Wait()
	file, _ := json.MarshalIndent(allservers, "", " ")
	_ = ioutil.WriteFile(filename, file, 0644)
	log.Println("Crawled", len(allservers))
	return ConvOoklatoDB(allservers, cfg)
	/*	if len(cfg.SearchASN) > 0 && len(cfg.SearchProvider) > 0 && len(cfg.SearchCountry) > 0 {
			log.Fatal("Only can search with one criteria")
		} else if len(cfg.SearchASN) > 0 {
			for _, j := range allservers {
				if j.ASN == cfg.SearchASN {
					fmt.Println(j.IPv4)
				}
			}
		} else if len(cfg.SearchProvider) > 0 {
			for _, j := range allservers {
				if strings.Contains(j.Sponsor, cfg.SearchProvider) {
					fmt.Println(j.IPv4)
				}
			}
		} else if len(cfg.SearchCountry) > 0 {
			for _, j := range allservers {
				if strings.Contains(j.CountryCode, cfg.SearchCountry) {
					fmt.Println(j.IPv4)
				}
			}
		}*/
	/*	for _, j := range allservers {
		fmt.Println(j.Id, j.Host)
	}*/
}

func QueryServers(hints string, results chan ResultsCarrier, wchan chan int) {
	qstring := fmt.Sprintf(OoklaQuery, hints)
	response, err := http.Get(qstring)
	if err != nil {
		log.Fatal(err)
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	rspobj := []OoklaServer{}
	json.Unmarshal(responseData, &rspobj)
	resultobj := ResultsCarrier{Hint: hints, Servers: rspobj}
	results <- resultobj
	time.Sleep(1 * time.Second)
	wg.Done()
	<-wchan
}

func ResultCollector(rchan chan ResultsCarrier) {
	servermap := make(map[string]bool)
	for r := range rchan {
		//		log.Println("Result", r.Hint, "contains", len(r.Servers), "records")
		for _, server := range r.Servers {
			if _, sexist := servermap[server.Id]; !sexist {
				//only insert those had not seen before
				servermap[server.Id] = true
				allservers = append(allservers, server)
			}
		}
		//got max number of record, need one level deeper
		if len(r.Servers) == MaxRecord {
			newlen := len(r.Hint) + 1
			if _, hexist := hintsmap[newlen]; !hexist {
				hintsmap[newlen] = GenerateHints(r.Hint, 1)
			} else {
				hintsmap[newlen] = append(hintsmap[newlen], GenerateHints(r.Hint, 1)...)
			}
		}
	}

}
func ResolveIP(serveridx int, iph iputils.IPHandler, wchan chan int) {
	allservers[serveridx].IPv4, allservers[serveridx].ASN = iph.ResolveV4(allservers[serveridx].Host)
	wg.Done()
	<-wchan
}

//generate all combination of a-z with length len
func GenerateHints(hint string, len int) []string {
	if len <= 0 {
		return []string{hint}
	}
	hints := []string{}
	for a := int('a'); a <= int('z'); a++ {
		newhint := hint + string(a)
		hints = append(hints, GenerateHints(newhint, len-1)...)
	}
	return hints
}
