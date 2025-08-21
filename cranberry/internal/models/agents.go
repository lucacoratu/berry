package models

import (
	"encoding/json"
	"io"
)

type RegisterAgentResponse struct {
	Uuid string `json:"uuid"`
}

func (reg *RegisterAgentResponse) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(reg)
}

func (reg *RegisterAgentResponse) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(reg)
}
