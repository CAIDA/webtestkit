package spdb

import "time"

type JSONPoint struct {
	Type  string    `json:"type"`
	Coord []float64 `json:"coordinates"`
}

type OoklaInfo struct {
	CountryCode string `json:"cc"`
	Sponsor     string `json:"sponsor"`
	Https       int    `json:"https_functional"`
	Url         string `json:"url"`
}

type MlabInfo struct {
	Url     string   `json:"url"`
	Version []string `json:"version"`
}

type SpeedServer struct {
	Type        string      `json:"type"`
	Id          string      `json:"id"`
	Location    JSONPoint   `json:"location"`
	Country     string      `json:"country"`
	Host        string      `json:"host"`
	City        string      `json:"city"`
	IPv4        string      `json:"ipv4"`
	IPv6        string      `json:"ipv6"`
	Asnv4       string      `json:"asn"`
	Enabled     bool        `json:"enabled"`
	LastUpdated time.Time   `json:"lastupdated"`
	Additional  interface{} `json:"additional"`
}
