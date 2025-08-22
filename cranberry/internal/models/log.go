package models

import (
	"encoding/json"
	"io"
)

// This structure holds the log data that is sent to the api
type LogData struct {
	AgentId          string         `json:"agentId"`          //The UUID of the agent that collected the log data
	RemoteIP         string         `json:"remoteIp"`         //The IP address of the sender of the request
	Timestamp        int64          `json:"timestamp"`        //Timestamp when the request was received
	Type             string         `json:"type"`             //The log type which can be http, websocket, tcp, udp (the same as the implemented handlers)
	Request          string         `json:"request"`          //The request base64 encoded. this can be empty when the message is coming from backend server to the client
	Response         string         `json:"response"`         //The response base64 encoded. this can be empty when the message is coming from client to backend server
	RequestFindings  []*FindingData `json:"requestFindings"`  //The list of findings on the request
	ResponseFindings []*FindingData `json:"responseFindings"` //The list of findings on the response
	Verdict          string         `json:"verdict"`          //The action which was taken (drop/allow)
}

// Convert json data to LogData structure
func (ld *LogData) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(ld)
}

// Convert LogData structure to json string
func (ld *LogData) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(ld)
}

type ExtendedLogData struct {
	LogData
	//Fields for HTTP type
	HTTPMethod          string `json:"httpMethod"`
	HTTPRequestVersion  string `json:"httpRequestVersion"`
	HTTPRequestURL      string `json:"httpRequestURL"`
	HTTPResponseVersion string `json:"httpResponseVersion"`
	HTTPResponseCode    string `json:"httpResponseCode"`
}

type ViewExtendedLogData struct {
	Id string `json:"id"` //This field is the id which will be retrieved from opensearch
	ExtendedLogData
}

type ViewExtendedLogsData []ViewExtendedLogData

func (veld *ViewExtendedLogsData) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(veld)
}
