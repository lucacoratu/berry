package websocket

import (
	"sync"
	"time"

	"blueberry/internal/config"
	"blueberry/internal/logging"

	"github.com/gorilla/websocket"
)

type message struct {
	Type int    `json:"type"`
	Body string `json:"body"`
}

type APIWebSocketConnection struct {
	logger        logging.ILogger      //The logger
	apiWsURL      string               //The ws url of the API
	configuration config.Configuration //The configuration structure of the agent
	State         bool                 //The state of the websocket connection (true for active, false for inactive)
	connection    *websocket.Conn      //The connection structure
	mu            sync.Mutex           //Mutex for the websocket connection
}

func NewAPIWebSocketConnection(logger logging.ILogger, apiWsURL string, configuration config.Configuration) *APIWebSocketConnection {
	return &APIWebSocketConnection{logger: logger, apiWsURL: apiWsURL, configuration: configuration}
}

// Connects to the API websocket URL for the agent
func (awsc *APIWebSocketConnection) Connect() (bool, error) {
	//Connect to the websocket URL from the API
	c, _, err := websocket.DefaultDialer.Dial(awsc.apiWsURL, nil)

	//Check if an error occured
	if err != nil {
		return false, err
	}

	awsc.connection = c
	awsc.State = true
	return true, nil
}

// // Handle the connection closed
// func (awsc *APIWebSocketConnection) connectionClosed(code int, text string) error {
// 	return nil
// }

// Handle the message received
func (awsc *APIWebSocketConnection) handleReceivedMessage(message message) {
	awsc.logger.Debug("Message received", message)
}

func (awsc *APIWebSocketConnection) Start() {
	//Close the connection at the end of the function
	defer awsc.connection.Close()

	//Start listening for incomming messages
	for {
		mt, msg, err := awsc.connection.ReadMessage()
		if err != nil {
			//Wait a bit then retry the connection
			awsc.logger.Error(err.Error())
			time.Sleep(time.Second * 10)
			_, err = awsc.Connect()
			if err == nil {
				//Connection was restored
				awsc.logger.Info("WebSocket connection to the API has been restored")
			}
			//Enter in the loop from the beginning to read the next message
			continue
		}

		//Call the handle message function
		awsc.handleReceivedMessage(message{Type: mt, Body: string(msg)})
	}
}

// Function to send a notification to the API
func (awsc *APIWebSocketConnection) SendNotification(message string) error {
	notif := Notification{AgentId: awsc.configuration.UUID, Message: message}
	return awsc.connection.WriteJSON(WebSocketMessage{Type: WsNotification, Data: notif})
}

// Function to send an alert when a high or critical payload is detected
func (awsc *APIWebSocketConnection) SendRuleDetectionAlert(alert RuleDetectionAlert) error {
	awsc.mu.Lock()
	err := awsc.connection.WriteJSON(WebSocketMessage{Type: WsRuleDetectionAlert, Data: alert})
	awsc.mu.Unlock()
	return err
}
