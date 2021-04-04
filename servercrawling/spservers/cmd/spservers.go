package main

import (
	"flag"
	"log"
	"os"
	"spservers/comcast"
	"spservers/common"
	"spservers/mlab"
	"spservers/ookla"
	"time"
)

func main() {
	cfg := common.Config{StartTime: time.Now(), Workers: 10}
	flag.StringVar(&cfg.CreateFilePrefix, "d", "", "Path to output files")
	flag.IntVar(&cfg.Workers, "w", 10, "Number of workers")
	flag.Parse()
	if len(cfg.CreateFilePrefix) > 0 {
		if _, err := os.Stat(cfg.CreateFilePrefix); os.IsNotExist(err) {
			err := os.MkdirAll(cfg.CreateFilePrefix, 0744)
			if err != nil {
				mbot.SendPanic("Create output directory error" + err.Error())
				log.Fatal(err)
			}
		}
	}
	oser := ookla.LoadOokla(&cfg)
	cser := comcast.LoadComcastServer(&cfg)
	mser := mlab.LoadMlab(&cfg)
	log.Printf("Summary: Ookla %d, Comcast %d, Mlab %d\n", oser, cser, mser)
}
