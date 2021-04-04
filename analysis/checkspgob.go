package main

import (
	"cloudanalysis/ookla"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	//	speedtestplatform := []string{"comcast"}
	//	nodes := []string{""}
	datapath := ""
	nworkers := 10
	cleanrun := false
	toverify := true
	wptr := flag.Int("worker", nworkers, "number of workers")
	cptr := flag.Bool("clean", cleanrun, "clean run (remove and rebuild gob)")
	vptr := flag.Bool("verifier", toverify, "verify the correctness of the algorithm")
	flag.StringVar(&datapath, "path", "/Users/raina/Desktop/test_data", "data path")
	flag.Parse()
	nworkers = *wptr
	cleanrun = *cptr
	toverify = *vptr
	workerchan := make(chan int, nworkers)
	var wg sync.WaitGroup
	var tmpdir string
	var err error
	if filepath.Ext(datapath) == ".bz2" {
		tmpdir, err = ioutil.TempDir(".", "chgob_")
		if err != nil {
			log.Fatal(err)
		}
		abspath, err := filepath.Abs(datapath)
		if err != nil {
			log.Fatal("abs path error", err)
		}
		log.Println("Working on", abspath)
		tarout, tarerr := exec.Command("tar", "-xvf", abspath, "-C", tmpdir).Output()
		//		err = tarcmd.Run()
		log.Printf("tar output: %s\n", tarout)
		log.Printf("tar command stderr: %v\n", tarerr)

		//for _, nd := range nodes {
		//	for _, platform := range speedtestplatform {
		//basepath := filepath.Join(tmpdir)
		/*			if cleanrun {
					gobsearch := filepath.Join(basepath, "*.gob")
					gobfiles, err := filepath.Glob(gobsearch)
					if err == nil {
						for _, gfile := range gobfiles {
							_ = os.Remove(gfile)
						}
					}
				}*/
		//		filesearch := filepath.Join(basepath, "*.json")
		//		files, err := filepath.Glob(filesearch)
		if tarerr == nil {
			taroutarr := strings.Split(fmt.Sprintf("%s", tarout), "\n")
			for _, jfile := range taroutarr {
				if len(jfile) > 1 && filepath.Ext(jfile) == ".gob" {
					workerchan <- 1
					absjfile := filepath.Join(tmpdir, jfile)
					log.Println("File:", absjfile)
					wg.Add(1)
					go ookla.RunOoklaAnalysis(&wg, workerchan, absjfile, toverify)
					/*switch platform {
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
					}*/
				}
			}

		}
		//	}
		//}
		wg.Wait()
	}
}
