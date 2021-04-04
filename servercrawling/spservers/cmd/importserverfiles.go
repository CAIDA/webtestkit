package main

import (
	"log"
	"os"
	"spservers/comcast"
	"spservers/common"
	"spservers/mlab"
	"spservers/ookla"
	"spservers/spdb"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 0 {
		log.Fatal("importserverfiles <serverlist.json> <mongoconfig> <ts>")
	}
	cfg := &common.Config{}
	serverlistfile := os.Args[1]
	cfg.MongoConfigFile = os.Args[2]
	ts, _ := strconv.ParseInt(os.Args[3], 10, 64)
	cfg.StartTime = time.Unix(ts, 0)
	db := spdb.NewMongoDB(cfg.MongoConfigFile, "speedtest")
	if db.Client == nil {
		log.Fatal("Connect mongodb error")
	}
	defer db.Close()
	var servers []spdb.SpeedServer
	if strings.Contains(serverlistfile, "ookla") {
		servers = ookla.ImportOoklaServerfromFile(cfg, serverlistfile)
		log.Println("loaded ", len(servers), "ookla servers")
	}
	if strings.Contains(serverlistfile, "ndt") {
		servers = mlab.ImportNdtServerfromFile(cfg, serverlistfile)
		log.Println("loaded ", len(servers), "ookla servers")
	}
	if strings.Contains(serverlistfile, "comcast") {
		servers = comcast.ImportComcastServerfromFile(cfg, serverlistfile)
		log.Println("loaded ", len(servers), "comcast servers")
	}
	db.InsertServers(servers)

}
