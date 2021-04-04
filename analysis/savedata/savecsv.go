package savedata

import (
	"encoding/csv"
	"log"
	"os"
)

type SaveCSV struct {
	Name string
	Fp   *os.File
	Data [][]string
}

func (mycsv *SaveCSV) NewCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("Fail to create CSV", filename, err)
	}
	mycsv.Name = filename
	mycsv.Fp = file
	mycsv.Data = make([][]string, 0)
	return err
}

func (mycsv *SaveCSV) CloseCSV() error {
	if mycsv.Fp != nil {
		w := csv.NewWriter(mycsv.Fp)
		for _, value := range mycsv.Data {
			if err := w.Write(value); err != nil {
				log.Fatal("Error writing CSV", err)
			}
		}
		w.Flush()
		return mycsv.Fp.Close()
	} else {
		log.Fatal("Please init CSV object")
		return nil
	}
}

//Append one element to csv data, no actual write
func (mycsv *SaveCSV) AddOneToCSV(data []string) {
	if mycsv.Fp != nil {
		mycsv.Data = append(mycsv.Data, data)
	} else {
		log.Fatal("Please init CSV object")
	}
}
