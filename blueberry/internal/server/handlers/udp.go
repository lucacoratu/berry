package handlers

import (
	"blueberry/internal/config"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/logging"
	"blueberry/internal/websocket"
	"net"
	"sync"
)

// Structure which holds all the necessary variables for UDP handler
type BlueberryUDPHandler struct {
	logger           logging.ILogger
	apiBaseURL       string                            //The API base URL
	configuration    config.Configuration              //The configuration structure
	forwardServerUrl string                            //The URL the requests should be forwarded to
	checkers         []code.IValidator                 //The list of validators which will be run on the request and the response to find malicious activity
	rules            []rules.Rule                      //The list of rules which will try to find anomalies in the requests and the responses
	apiWsConn        *websocket.APIWebSocketConnection //The WS connection to the API
	//TODO add global mutex for api websocket connection
	targetUdpServer net.Conn
	targetUdpMutex  sync.Mutex
}

func NewBlueberryUDPHandler(logger logging.ILogger, apiBaseURL string, configuration config.Configuration, forwardServerURL string, checkers []code.IValidator, rules []rules.Rule, apiWsConn *websocket.APIWebSocketConnection) *BlueberryUDPHandler {
	return &BlueberryUDPHandler{
		logger:           logger,
		apiBaseURL:       apiBaseURL,
		configuration:    configuration,
		forwardServerUrl: forwardServerURL,
		checkers:         checkers,
		rules:            rules,
		apiWsConn:        apiWsConn,
	}
}

func (buh *BlueberryUDPHandler) HandleUDPConnection(conn net.Conn) {
	conn.Close()
}
