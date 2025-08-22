package models

import (
	"encoding/json"
	"io"
	"time"
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

// Structure which will be sent when an agent is requested by the client
type ViewAgentResponse struct {
	ID            uint      `json:"id"`
	UUID          string    `json:"uuid"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"createdAt"`
	LogsCollected uint      `json:"logsCollected"`
}

func (vag *ViewAgentResponse) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(vag)
}

type ViewAgentsResponse []ViewAgentResponse

func (vasg ViewAgentsResponse) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(vasg)
}
