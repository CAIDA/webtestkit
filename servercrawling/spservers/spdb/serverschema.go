package spdb

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type JSONPoint struct {
	Type  string    `json:"type"`
	Coord []float64 `json:"coordinates" bson:"coordinates"`
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
	SpId        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Type        string             `json:"type"`
	Id          string             `json:"id"`
	Identifier  string             `json:"identifier"`
	Location    JSONPoint          `json:"location"`
	Country     string             `json:"country"`
	Host        string             `json:"host"`
	City        string             `json:"city"`
	IPv4        string             `json:"ipv4"`
	IPv6        string             `json:"ipv6"`
	Asnv4       string             `json:"asn"`
	Enabled     bool               `json:"enabled"`
	LastUpdated time.Time          `json:"lastupdated"`
	Additional  interface{}        `json:"additional"`
}

type VMDataStatus struct {
	Mon        string `json:"mon"`
	BdrmapFile string `json:"bdrmapfile"`
	TraceFile  string `json:"trfile"`
}

//struct for storing interdomain link
type Link struct {
	LinkId   primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Region   string             `json:"region"`
	Linkkey  string             `json:"linkkey"`
	NearIP   string             `json:"nearip"`
	FarIP    string             `json:"farip"`
	FarAS    string             `json:"faras"`
	LastSeen []int64            `json:"lastseen"`
	Current  bool               `json:"current"`
	Covered  bool               `json:"covered"`
}

type Traceroute struct {
	Region     string             `json:"region"`
	DstIP      string             `json:"dstip"`
	DstAS      string             `json:"dstas"`
	SpServerId primitive.ObjectID `json:"speedserverid"`
	LinkId     primitive.ObjectID `json:"linkid"`
	Ts         int64              `json:"ts"`
	Hops       []TrHop            `json:"hops"`
}

type TrHop struct {
	Addr     string  `json:"addr"`
	ProbeTTL int     `json:"probettl"`
	Rtt      float64 `json:"rtt"`
	Asn      string  `json:"asn"`
}

type TimePeriod struct {
	Start time.Time
	End   time.Time
}

type SpeedMeas struct {
	Mon          string             `json: "mon" bson:"mon"`
	SpeedServer  primitive.ObjectID `json:"speedserver" bson:"speedserver"`
	Link         primitive.ObjectID `json:"link" bson:"link"`
	Enabled      bool               `json: "enabled" bson:"enabled"`
	Activeperiod []TimePeriod       `json:"activeperiod" bson:"activeperiod"`
	Assigntype   string             `json:"assigntype" bson:"assigntype"`
	Reason       int                `json:"reason" bson:"reason"`
}
