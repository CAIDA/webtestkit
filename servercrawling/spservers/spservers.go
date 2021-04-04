package main

import (
	"flag"
	"fmt"
	"log"
	"mmbot"
	"os"
	"spservers/comcast"
	"spservers/common"
	"spservers/mlab"
	"spservers/ookla"
	"spservers/spdb"
	"time"
)

func main() {
	cfg := common.Config{StartTime: time.Now(), Workers: 10}
	flag.StringVar(&cfg.BotConfigFile, "b", "mattermostbot.json", "Config file for posting to mattermost")
	flag.StringVar(&cfg.MongoConfigFile, "m", "beamermongosp.json", "Config file for accessing mongodb")
	flag.BoolVar(&cfg.EnableMM, "M", true, "Enable mattermost posting")
	flag.StringVar(&cfg.CreateFilePrefix, "d", "", "Path to output files")
	flag.IntVar(&cfg.Workers, "w", 10, "Number of workers")
	flag.Parse()
	if !cfg.EnableMM {
		cfg.BotConfigFile = ""
	}
	mbot := mmbot.NewMMBot(cfg.BotConfigFile)
	if _, err := os.Stat(cfg.CreateFilePrefix); os.IsNotExist(err) {
		err := os.MkdirAll(cfg.CreateFilePrefix, 0744)
		if err != nil {
			mbot.SendPanic("Create output directory error" + err.Error())
			log.Fatal(err)
		}
	}
	db := spdb.NewMongoDB(cfg.MongoConfigFile, "speedtest")
	if db.Client == nil {
		mbot.SendPanic("Connect mongodb error")
		log.Fatal("Connect mongodb error")
	}
	defer db.Close()
	db.ResetEnable("ookla")
	oser := ookla.LoadOokla(&cfg)
	oknewser, err := db.InsertServers(oser)
	if err != nil {
		log.Panic(err)
		mbot.SendPanic("I got panic when crawling Ookla server " + err.Error())
	} else {
		log.Println("Inserted ", oknewser)
	}
	db.ResetEnable("comcast")
	cser := comcast.LoadComcastServer(&cfg)
	cnewser, err := db.InsertServers(cser)
	if err != nil {
		log.Panic(err)
		mbot.SendPanic("I got panic when crawling Comcast server " + err.Error())
	} else {
		log.Println("Inserted ", cnewser)
	}
	db.ResetEnable("mlab")
	mser := mlab.LoadMlab(&cfg)
	mnewser, err := db.InsertServers(mser)
	if err != nil {
		log.Panic(err)
		mbot.SendPanic("I got panic when crawling Mlab server " + err.Error())
	} else {
		log.Println("Inserted new", mnewser)
	}
	msgstring := fmt.Sprintf("I crawled %d (new: %d) Ookla servers, %d (new: %d) Comcast servers, %d (new: %d) Mlab servers. ", len(oser), oknewser, len(cser), cnewser, len(mser), mnewser)
	mbot.SendInfo(msgstring)
}
