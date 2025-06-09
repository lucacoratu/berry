package websocket

import (
	"encoding/json"
	"io"
)

// Message Types
const (
	WsError                         int64 = -1
	WsNotification                  int64 = 1
	WsAgentStatusRequest            int64 = 2
	WsAgentStatusResponse           int64 = 3
	WsAgentDisconnectedNotification int64 = 4
	WsAgentConnectedNotification    int64 = 5
	WsRuleDetectionAlert            int64 = 6
)

// WebSocket message format
type WebSocketMessage struct {
	Type int64       `json:"type"` //The type of the message
	Data interface{} `json:"data"` //The data of the message as interface (can be any struct)
}

func (wsm *WebSocketMessage) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(wsm)
}

func (wsm *WebSocketMessage) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(wsm)
}

// Notification Websocket message
type Notification struct {
	AgentId string `json:"agentId"`
	Message string `json:"message"`
}

func (not *Notification) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(not)
}

type AgentStatusRequest struct {
	AgentId string `json:"agentId"`
}

func (asr *AgentStatusRequest) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(asr)
}

type AgentStatusResponse struct {
	AgentId string `json:"agentId"`
	Status  string `json:"status"`
}

func (asr *AgentStatusResponse) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(asr)
}

type RuleDetectionAlert struct {
	AgentId         string `json:"agentId"`
	RuleId          string `json:"ruleId"`
	RuleName        string `json:"ruleName"`
	RuleDescription string `json:"ruleDescription"`
	Classification  string `json:"classification"`
	Severity        string `json:"severity"`
	Timestamp       int64  `json:"timestamp"`
}

func (rda *RuleDetectionAlert) FromJSON(r io.Reader) error {
	e := json.NewDecoder(r)
	return e.Decode(rda)
}
