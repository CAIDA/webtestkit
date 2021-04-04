package common

import (
	"log"
	"os"
	"path/filepath"
)

type FilePaths struct {
	Pcap          string
	PcapExist     bool
	SSLKey        string
	SSLKeyExist   bool
	WebCSV        string
	WebCSVExist   bool
	MetaData      string
	MetaDataExist bool
	Netlog        string
	NetlogExist   bool
	Tracelog      string
	TracelogExist bool
}

//input is the abs path to the tracing json file
func CheckDataFiles(tracefilepath string) *FilePaths {
	_, err := os.Stat(tracefilepath)
	if err != nil {
		log.Fatal("No tracefile", tracefilepath)
	}
	basename := tracefilepath[:len(tracefilepath)-len(filepath.Ext(tracefilepath))]
	fp := &FilePaths{Pcap: basename + ".pcap", SSLKey: basename + ".key", WebCSV: basename + ".web.csv", MetaData: basename + ".meta.json", Netlog: basename + ".netlog", Tracelog: tracefilepath}
	fp.TracelogExist = true
	_, err = os.Stat(fp.Pcap)
	fp.PcapExist = (err == nil)
	_, err = os.Stat(fp.SSLKey)
	fp.SSLKeyExist = (err == nil)
	_, err = os.Stat(fp.WebCSV)
	fp.WebCSVExist = (err == nil)
	_, err = os.Stat(fp.MetaData)
	fp.MetaDataExist = (err == nil)
	_, err = os.Stat(fp.Netlog)
	fp.NetlogExist = (err == nil)
	return fp
}
