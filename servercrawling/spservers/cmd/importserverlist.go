package main

import (
	"bufio"
	"log"
	"os"
	"spservers/spdb"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Println("usage: go run importserverlist.go <serverlist>")
	}
	serfile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer serfile.Close()
	mgo := spdb.NewMongoDB("/scratch/cloudspeedtest/bin/beamermongosp.json", "speedtest")
	if mgo == nil {
		log.Fatal("mongo error")
	}
	defer mgo.Close()
	servmeas := make([]*spdb.SpeedMeas, 0)
	scanner := bufio.NewScanner(serfile)
	for scanner.Scan() {
		line := strings.Split(strings.TrimSpace(scanner.Text()), "|")

		if len(line) == 5 {
			method := line[3]
			if method == "ndt" {
				method = "mlab"
			}
			if spserver, err := mgo.QueryServerbyIdentifier(method, line[4]); err == nil {
				if link, errl := mgo.QueryLinkbyFar(line[0], line[1]); errl == nil {
					ts := spdb.TimePeriod{Start: time.Unix(1588291200, 0)}
					var smeas *spdb.SpeedMeas
					if len(link) > 0 {
						smeas = &spdb.SpeedMeas{Mon: line[0], SpeedServer: spserver.SpId, Link: link[0].LinkId, Enabled: true, Assigntype: "auto", Activeperiod: []spdb.TimePeriod{ts}}
					} else {
						log.Println("link not found", line[0], line[1])
						smeas = &spdb.SpeedMeas{Mon: line[0], SpeedServer: spserver.SpId, Enabled: true, Assigntype: "auto", Activeperiod: []spdb.TimePeriod{ts}}
					}
					servmeas = append(servmeas, smeas)
				}
			} else {
				log.Println("server not found", line[3], line[4])
			}
		}
	}
	inserted, err := mgo.InsertManySpeedMeas(servmeas)
	log.Println("Inserted", inserted, "assignment")
}
