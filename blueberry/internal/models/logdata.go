package data

import (
	"encoding/json"
	"io"
)

// This structure holds the log data that is sent to the api
type LogData struct {
	//Id           string        `json:"id"`           //The UUID of the log from the database
	AgentId      string        `json:"agentId"`      //The UUID of the agent that collected the log data
	RemoteIP     string        `json:"remoteIp"`     //The IP address of the sender of the request
	Timestamp    int64         `json:"timestamp"`    //Timestamp when the request was received
	Websocket    bool          `json:"websocket"`    //If the log is from a websocket message
	Request      string        `json:"request"`      //The request base64 encoded
	Response     string        `json:"response"`     // The response base64 encoded
	Findings     []Finding     `json:"findings"`     //A list of findings
	RuleFindings []RuleFinding `json:"ruleFindings"` //The list of rule findings
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
