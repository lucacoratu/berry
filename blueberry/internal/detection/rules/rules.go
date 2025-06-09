package detection

import (
	"io"

	"gopkg.in/yaml.v2"
)

// Holds all the information in the info field of the rule.yaml files
type RuleInfo struct {
	Name           string   `yaml:"name"`           //The name of the rule
	Description    string   `yaml:"description"`    //The description of the rule
	Severity       string   `yaml:"severity"`       //The severity of the rule, in the string representation
	Classification string   `yaml:"classification"` //The classification if it matches, in the string representation
	Action         string   `yaml:"action"`         //The action that should be taken if anything matches the rule (only for waf operation mode) (drop or allow)
	Encodings      []string `yaml:"encodings"`      //The encodings supported when searching (this will apply to all the fields)
}

// Holds all the modes the hex search can be made
type RuleHexSearchMod struct {
	Match string `yaml:"match"` //The hex string to find
	Regex string `yaml:"regex"` //The regex (as hex - except regex special chars) to match
}

// Holds all the modes the search can be made
type RuleSearchMode struct {
	Match     string   `yaml:"match"`     //The string to match exactly
	Regex     string   `yaml:"regex"`     //The regex used for searching
	Encodings []string `yaml:"encodings"` //The encodings supported when searching
}

// Holds all the information about headers
type HeadersRule struct {
	Name      string   `yaml:"name"`      //The name of the search to search for matches
	Match     string   `yaml:"match"`     //The string to match exactly
	Regex     string   `yaml:"regex"`     //The regex used for searching
	Encodings []string `yaml:"encodings"` //The encodings supported when searching
}

// Holds all the information about request parameters
type RequestParametersRule struct {
	Name      string   `yaml:"name"`      //The name of the query variable (can be any which means look through all the query variable names for a match)
	Match     string   `yaml:"match"`     //The string to match exactly
	Regex     string   `yaml:"regex"`     //The regex used for searching
	Encodings []string `yaml:"encodings"` //The encodings supported when searching
}

// Holds all the information about the body
type BodyRule struct {
	SHA256Sum string   `yaml:"sha256sum"` //The SHA256 hash of the body to match
	MD5Sum    string   `yaml:"md5sum"`    //The MD5 hash of the body
	Match     string   `yaml:"match"`     //The string to match exactly
	Regex     string   `yaml:"regex"`     //The regex used for searching
	Encodings []string `yaml:"encodings"` //The encodings supported when searching
}

// Holds all the information about the websocket message
type WebsocketRule struct {
	MessageType int    `yaml:"message_type"` //The type of the websocket message (can be 1 - TextMessage, 2 - BinaryMessage, 8 - CloseMessage, 9 - PingMessage, 10 - PongMessage) RFC 6455, section 11.8.
	Match       string `yaml:"match"`        //The string to find in message
	Regex       string `yaml:"regex"`        //The regex used for matching
	HexMatch    string `yaml:"hexmatch"`     //The hexstring to find in message
	HexRegex    string `yaml:"hexregex"`     //The regex which contains hex bytes used for matching
}

// Holds all the information in the request field of the rule YAML file
type RequestRule struct {
	Method     *RuleSearchMode          `yaml:"method"`  //The modes to search on the method
	URL        []*RuleSearchMode        `yaml:"url"`     //The modes to search on the URL
	Headers    []*HeadersRule           `yaml:"headers"` //The headers to be checked
	Parameters []*RequestParametersRule `yaml:"params"`  //The request parameters (both from URL and body)
	Body       []*BodyRule              `yaml:"body"`    //The string to search for in the body
}

// Holds all the information in the response field of the rule YAML file
type ResponseRule struct {
	Code    *RuleSearchMode `yaml:"code"`    //The modes to search on the status code
	Headers []*HeadersRule  `yaml:"headers"` //The headers to be checked
	Body    []*BodyRule     `yaml:"body"`    //The string to search for in the body
}

// Structure which holds all the information about the rule parsed from the rule.yaml file
type Rule struct {
	Id        string           `yaml:"id"`        //The ID of the rule (should be unique)
	Info      *RuleInfo        `yaml:"info"`      //The info structure
	Request   *RequestRule     `yaml:"request"`   //The request matchers
	Response  *ResponseRule    `yaml:"response"`  //The response matchers
	Websocket []*WebsocketRule `yaml:"websocket"` //The websocket matchers
}

// Function to read the yaml rule from a reader into the struct
func (yr *Rule) FromYAML(r io.Reader) error {
	d := yaml.NewDecoder(r)
	return d.Decode(yr)
}

// Holds all the information about the matched hash of the body
type BodyHashMatch struct {
	BodyHash          string
	BodyHashAlgorithm string
}
