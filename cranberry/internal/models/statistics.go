package models

import (
	"encoding/json"
	"io"
)

type HTTPMethodStatistics struct {
	GET     int64 `json:"GET"`
	HEAD    int64 `json:"HEAD"`
	OPTIONS int64 `json:"OPTIONS"`
	TRACE   int64 `json:"TRACE"`
	PUT     int64 `json:"PUT"`
	DELETE  int64 `json:"DELETE"`
	POST    int64 `json:"POST"`
	PATCH   int64 `json:"PATCH"`
	CONNECT int64 `json:"CONNECT"`
}

// Convert HTTPMethodStatistics structure to json string
func (hms *HTTPMethodStatistics) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(hms)
}
