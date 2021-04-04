package savedata

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
)

func SaveData(path string, data interface{}) error {
	file, err := os.Create(path)
	defer file.Close()
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(data)
	}
	return err
}

func LoadData(path string, data interface{}) error {
	file, err := os.Open(path)
	defer file.Close()
	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(data)
	}
	return err
}

//cut out the extension (.json) and replace it with .gob
func GobName(path string) string {
	ext := filepath.Ext(path)
	return path[:len(path)-len(ext)] + ".gob"
}

func SaveJSON(path, postfix string, data interface{}) error {
	var buf bytes.Buffer
	ext := filepath.Ext(path)
	p := path[:len(path)-len(ext)] + postfix
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Panic("SaveJSON error", err)
	}
	enc := json.NewEncoder(&buf)
	enc.Encode(data)
	_, err = io.WriteString(f, buf.String())
	return err
}
