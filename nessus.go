package nessus

import (
	"bytes"
	"encoding/xml"

	"golang.org/x/net/html/charset"
)

// Parse Nessus Report XML provided as a []byte
// Returns a NessusData struct
func Parse(content []byte) (NessusData, error) {
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.CharsetReader = charset.NewReaderLabel
	dec.Strict = false

	var doc NessusData
	if err := dec.Decode(&doc); err != nil {
		return doc, err
	}

	return doc, nil
}
