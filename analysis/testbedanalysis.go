package main

import (
	"analysis/comcast"
	"analysis/fast"
	"analysis/ndt"
	"analysis/ookla"
	"analysis/speedofme"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	var datapath string
	speedtestplatform := []string{"comcast", "ookla"}

	/*	host_file, err := os.Open("/home/ubuntu/cloudhosts")
		if err != nil {
			log.Fatal(err)
		}
		defer host_file.Close()
		scanner := bufio.NewScanner(host_file)
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			if words[2] == "amazon"{
				nodes = append(nodes, words[0])
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

	*/
	nworkers := 10
	cleanrun := true
	toverify := true
	wptr := flag.Int("worker", nworkers, "number of workers")
	cptr := flag.Bool("clean", cleanrun, "clean run (remove and rebuild gob)")
	flag.StringVar(&datapath, "path", "~/Desktop/error", "data path")
	vptr := flag.Bool("verifier", toverify, "verify the correctness of the algorithm")

	//flag.StringVar(&datapath, "path", "/Users/yangrui/data", "data path")

	//flag.StringVar(&datapath, "path", "/scratch/webspeedtest", "data path")

	flag.Parse()
	nworkers = *wptr
	cleanrun = *cptr
	toverify = *vptr

	workerchan := make(chan int, nworkers)
	var wg sync.WaitGroup
	//	for _, nd := range nodes {
	for _, platform := range speedtestplatform {
		if cleanrun {
			gobsearch := datapath + "/" + platform + "/" + "*.gob"
			gobfiles, err := filepath.Glob(gobsearch)
			if err == nil {
				for _, gfile := range gobfiles {
					_ = os.Remove(gfile)
				}
			}
			rtt_json_search := datapath + "/" + platform + "/" + "*rtt.json"
			rtt_jsons, err := filepath.Glob(rtt_json_search)
			if err == nil {
				for _, gfile := range rtt_jsons {
					_ = os.Remove(gfile)
				}
			}
		}
		filesearch := datapath + "/" + platform + "/" + "*.json"

		files, err := filepath.Glob(filesearch)
		log.Println("files", filesearch)
		if err == nil {
			//// only try 5 files in each directory
			//if len(files) >= 5{
			//	files = files[0:5]
			//}

			for _, jfile := range files {
				if !strings.Contains(jfile, "meta") && !strings.Contains(jfile, "output") && !strings.Contains(jfile, "lost") {
					workerchan <- 1
					log.Println("File:", jfile)
					wg.Add(1)
					switch platform {
					case "comcast", "comcasttest":
						log.Println("enter")
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
		} else {
			log.Fatal(err)
		}
	}
	//	}

	wg.Wait()
	log.Println("Complete")
}
