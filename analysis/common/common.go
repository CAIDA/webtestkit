package common

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
)

func MarshalResult(v interface{}) (io.Reader, error) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func UnMarshalResult(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

func Getfilename(s string) string {
	sarr := strings.Split(s, "/")
	njsonarr := strings.Split(sarr[len(sarr)-1], ".")
	newpath := append(sarr[:len(sarr)-1], "plots", njsonarr[0])
	return strings.Join(newpath, "/")
}

func Makeplotdir(s string) {
	sarr := strings.Split(s, "/")
	newpath := append(sarr[:len(sarr)-1], "plots")
	_ = os.Mkdir(strings.Join(newpath, "/"), 0775)
}
