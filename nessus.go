package nessus

import (
	"bytes"
	"encoding/xml"
	"log"

	"golang.org/x/net/html/charset"
)

func Parse(content []byte) (NessusData, error) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.CharsetReader = charset.NewReaderLabel
	dec.Strict = false

	var doc NessusData
	if err := dec.Decode(&doc); err != nil {
		log.Fatal(err)
	}

	return doc, nil
}
