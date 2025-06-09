package data

import (
	"encoding/json"
	"io"
)

type RegisterProxyResponse struct {
	Uuid string `json:"uuid"`
}

func (reg *RegisterProxyResponse) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(reg)
}

func (reg *RegisterProxyResponse) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(reg)
}

type SuccessMessage struct {
	Message string `json:"message"`
}

func (sm *SuccessMessage) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(sm)
}

func (sm *SuccessMessage) ToJSON(w io.Writer) error {
	d := json.NewEncoder(w)
	return d.Encode(sm)
}

const (
	DATABASE_ERROR int64 = 1
	PARSE_ERROR    int64 = 2
)

type APIError struct {
	Code    int64  `json:"code"`    //The code of the error
	Message string `json:"message"` //The message of the error
}

// Convert from json into the APIError structure
func (err *APIError) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(err)
}

// Convert to json the APIError structure
func (err *APIError) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(err)
}
