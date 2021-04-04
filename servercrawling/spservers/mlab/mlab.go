package mlab

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"serverlinks/iputils"
	"spservers/common"
	"spservers/spdb"
	"strconv"
)

//choose from: ndt, ndt_ssl, ndt7
const NDTUrlTemplate = "https://mlab-ns.appspot.com/%s?policy=all"

const MLABSITES = "https://siteinfo.mlab-oti.measurementlab.net/v1/sites/locations.json"

//"https://storage.googleapis.com/operator-mlab-oti/metadata/v0/current/mlab-site-stats.json"
type NDTServer struct {
	IPs     []string `json:"ip"`
	IPv4    string   `json:"IPv4"`
	IPv6    string   `json:"IPv6"`
	City    string   `json:"city"`
	Url     string   `json:"url"`
	Host    string   `json:"fqdn"`
	Site    string   `json:"site"`
	Country string   `json:"country"`
	Version []string `json:"version"`
	Lat     float64  `json:"latitude"`
	Lon     float64  `json:"longitude"`
}

type NDTMeta struct {
	Site string  `json:"site"`
	Lat  float64 `json:"latitude"`
	Lon  float64 `json:"longitude"`
}

type ConfigNDT struct {
	NDTVersion    string
	CreateNDTFile string
	OpenNDTFile   string
	SelectCountry string
	IPFile        string
}

func convmlabtomongo(cfg *common.Config, ndt []NDTServer) []spdb.SpeedServer {
	spslice := make([]spdb.SpeedServer, len(ndt))
	iph := iputils.NewIPHandler()
	for nidx, nserver := range ndt {
		loc := spdb.JSONPoint{Type: "Point", Coord: []float64{nserver.Lon, nserver.Lat}}
		mlabinfo := spdb.MlabInfo{Url: nserver.Url, Version: nserver.Version}
		spslice[nidx] = spdb.SpeedServer{Type: "mlab", Id: nserver.Site, Identifier: nserver.Host, Location: loc, Country: nserver.Country, City: nserver.City, Host: nserver.Host, IPv4: nserver.IPv4, IPv6: nserver.IPv6, Asnv4: iph.IPv4toASN(net.ParseIP(nserver.IPv4)), Enabled: true, LastUpdated: cfg.StartTime, Additional: mlabinfo}
	}
	return spslice
}

func ImportNdtServerfromFile(cfg *common.Config, filename string) []spdb.SpeedServer {
	var allokserver []NDTServer
	jsonFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	serverstr, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(serverstr, &allokserver)
	return convmlabtomongo(cfg, allokserver)
}

func LoadMlab(cfg *common.Config) []spdb.SpeedServer {
	var allservers []NDTServer
	/*	cfg := &ConfigNDT{}
		flag.StringVar(&cfg.CreateNDTFile, "n", "", "Crawl and create NDT server json file")
		flag.StringVar(&cfg.OpenNDTFile, "o", "", "Open NDT server json file")
		flag.StringVar(&cfg.NDTVersion, "ver", "ndt", "Select NDT version")
		flag.StringVar(&cfg.SelectCountry, "country", "", "Select Country")
		flag.StringVar(&cfg.IPFile, "ip", "", "Filename for list of IP")
		flag.Parse()
	*/
	filename := "ndt_" + strconv.FormatInt(cfg.StartTime.Unix(), 10) + ".json"

	if len(cfg.CreateFilePrefix) > 0 {
		filename = filepath.Join(cfg.CreateFilePrefix, filename)
	}
	//if len(cfg.CreateNDTFile) > 0 {
	allservers = MergeNDTservers(LoadSiteMeta(), LoadNDTServers("ndt"), LoadNDTServers("ndt_ssl"), LoadNDTServers("ndt7"))
	file, _ := json.MarshalIndent(allservers, "", " ")
	_ = ioutil.WriteFile(filename, file, 0644)
	log.Println("loaded", len(allservers), "servers")
	return convmlabtomongo(cfg, allservers)
	/*} else {
		jsonFile, err := os.Open(cfg.OpenNDTFile)
		if err != nil {
			log.Fatal(err)
		}
		defer jsonFile.Close()
		bvalue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(bvalue, &allservers)
	}*/
	/*
		for _, s := range allservers {
			sort.Strings(s.Version)
			i := sort.SearchStrings(s.Version, cfg.NDTVersion)
			if s.Country == "US" && s.Version[i] == cfg.NDTVersion {
				fmt.Println(s.IPv4)
			}
		}
	*/
}

func LoadSiteMeta() []NDTMeta {
	log.Println("LoadSiteMeta")
	resp, err := http.Get(MLABSITES)
	if err != nil {
		log.Fatal(err)
	}
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	sitemeta := []NDTMeta{}
	json.Unmarshal(respData, &sitemeta)
	return sitemeta
}

func LoadNDTServers(version string) []NDTServer {
	log.Println("LoadNDTServers", version)
	qurl := fmt.Sprintf(NDTUrlTemplate, version)
	resp, err := http.Get(qurl)
	if err != nil {
		log.Fatal(err)
	}
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	servers := []NDTServer{}
	json.Unmarshal(respData, &servers)
	for sidx, server := range servers {
		servers[sidx].Version = []string{version}
		for _, ip := range server.IPs {
			if net.ParseIP(ip).To4() != nil {
				servers[sidx].IPv4 = ip
			} else {
				servers[sidx].IPv6 = ip
			}
		}
	}
	return servers
}

func MergeNDTservers(metadata []NDTMeta, ndts ...[]NDTServer) []NDTServer {
	ndtidmap := make(map[string]*NDTServer)
	metaidmap := make(map[string]int)
	allservers := make([]NDTServer, 0)
	for midx, meta := range metadata {
		if _, mexist := metaidmap[meta.Site]; !mexist {
			metaidmap[meta.Site] = midx
		}
	}

	for nidx, ndtserver := range ndts {
		for sidx, s := range ndtserver {
			if _, sexist := ndtidmap[s.Site]; !sexist {
				ndtidmap[s.Site] = &ndts[nidx][sidx]
				if _, mexist := metaidmap[s.Site]; mexist {
					ndtidmap[s.Site].Lat = metadata[metaidmap[s.Site]].Lat
					ndtidmap[s.Site].Lon = metadata[metaidmap[s.Site]].Lon
				} else {
					log.Println("No metadata", s.Site)
				}
			} else {
				ndtidmap[s.Site].Version = append(ndtidmap[s.Site].Version, s.Version[0])
			}
		}
	}
	for _, s := range ndtidmap {
		allservers = append(allservers, *s)
	}
	return allservers
}
