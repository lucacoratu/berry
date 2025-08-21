package models

import (
	"encoding/json"
	"io"
)

type CranberryAPIError struct {
	Detail string `json:"detail"`
}

func (ce *CranberryAPIError) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(ce)
}
