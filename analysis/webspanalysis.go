package main

import (
	"cloudanalysis/comcast"
	"cloudanalysis/fast"
	"cloudanalysis/ndt"
	"cloudanalysis/ookla"
	"cloudanalysis/speedofme"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	speedtestplatform := []string{"comcast"}
	nodes := []string{""}
	datapath := ""
	nworkers := 10
	cleanrun := false
	toverify := true
	wptr := flag.Int("worker", nworkers, "number of workers")
	cptr := flag.Bool("clean", cleanrun, "clean run (remove and rebuild gob)")
	vptr := flag.Bool("verifier",toverify, "verify the correctness of the algorithm")
	flag.StringVar(&datapath, "path", "/Users/raina/Desktop/test_data", "data path")
	flag.Parse()
	nworkers = *wptr
	cleanrun = *cptr
	toverify = *vptr
	workerchan := make(chan int, nworkers)
	var wg sync.WaitGroup
	for _, nd := range nodes {
		for _, platform := range speedtestplatform {
			basepath := filepath.Join(datapath, nd, platform)
			if cleanrun {
				gobsearch := filepath.Join(basepath, "*.gob")
				gobfiles, err := filepath.Glob(gobsearch)
				if err == nil {
					for _, gfile := range gobfiles {
						_ = os.Remove(gfile)
					}
				}
			}
			filesearch := filepath.Join(basepath, "*.json")
			files, err := filepath.Glob(filesearch)
			if err == nil {
				for _, jfile := range files {
					if !strings.Contains(jfile, "rtt") &&  !strings.Contains(jfile, "meta") &&  !strings.Contains(jfile, "gometa") && !strings.Contains(jfile, "output") && !strings.Contains(jfile, "lost") && !strings.Contains(jfile, "verify"){
						workerchan <- 1
						log.Println("File:", jfile)
						wg.Add(1)
						switch platform {
						case "comcast", "comcasttest":
							log.Println(platform)
							go comcast.RunComcastAnalysis(&wg, workerchan, jfile, toverify)
						case "fast", "fasttest":
							go fast.RunFastAnalysis(&wg, workerchan, jfile)
						case "ookla", "ooklatest":
							go ookla.RunOoklaAnalysis(&wg, workerchan, jfile, toverify)
						case "speedofme", "speedofmetest":
							go speedofme.RunSpeedofmeAnalysis(&wg, workerchan, jfile)

						case "ndt", "ndttest":
							go ndt.RunNdtAnalysis(&wg, workerchan, jfile)
						}
					}
				}

			}
		}
	}
	wg.Wait()
}
