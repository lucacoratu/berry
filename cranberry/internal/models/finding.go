package models

import (
	"encoding/json"
	"io"
)

// Severity types
const (
	LOW      int64 = 0
	MEDIUM   int64 = 1
	HIGH     int64 = 2
	CRITICAL int64 = 3
)

// Structure that will hold information about the findings
type FindingData struct {
	RuleId             string `json:"ruleId"`             //The rule id specified on the agent rule
	RuleName           string `json:"ruleName"`           //The name of the rule specified on the agent
	RuleDescription    string `json:"ruleDescription"`    //The description of the rule
	Line               int64  `json:"line"`               //The line from the request where the finding is located
	LineIndex          int64  `json:"lineIndex"`          //The offset from the start of the line
	Length             int64  `json:"length"`             //The length of the finding string
	MatchedString      string `json:"matchedString"`      //The string on which the rule matched
	MatchedBodyHash    string `json:"matchedBodyHash"`    //The hash of the body which matched
	MatchedBodyHashAlg string `json:"matchedBodyHashAlg"` //The algorithm used for hashing the body
	Classification     string `json:"classification"`     //The classification of the finding based on the string specified in the rule file
	Severity           int64  `json:"severity"`           //The severity of the finding
}

// Rule findings found by agent, one for request, one for response
type Finding struct {
	Request  *FindingData `json:"request"`  //The rule findings for the request
	Response *FindingData `json:"response"` //The rule findings for the response
}

// Convert rule finding to JSON
func (f *Finding) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(f)
}

// Convert rule finding from JSON
func (f *Finding) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(f)
}
