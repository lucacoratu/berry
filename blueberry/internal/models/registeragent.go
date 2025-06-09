package data

import (
	"encoding/json"
	"io"
)

// Holds data about the agent
type AgentInformation struct {
	Protocol          string             `json:"protocol"`            //The protocol the agent uses to communicate with the users
	IPAddress         string             `json:"ip_address"`          //The interface's IP address the agent is listening on
	Port              string             `json:"port"`                //The port the agent is running on
	WebServerProtocol string             `json:"webServerProtocol"`   //Protocol used to communicate to the webserver
	WebServerIP       string             `json:"webServerIP"`         //Address of the web server the agent is connected to
	WebServerPort     string             `json:"webServerPort"`       //Port of the web server the agent is connected to
	MachineInfo       MachineInformation `json:"machine_information"` //The information about the machine the agent is deployed on
}

func (agi *AgentInformation) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(agi)
}

func (agi *AgentInformation) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(agi)
}
