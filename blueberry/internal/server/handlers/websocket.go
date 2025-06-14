package handlers

import (
	"blueberry/internal/config"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/logging"
	"blueberry/internal/websocket"
	"fmt"
	"net/http"
	"net/url"

	ws_gorilla "github.com/gorilla/websocket"
)

type BlueberryWebsocketHandler struct {
	logger           logging.ILogger
	apiBaseURL       string                            //The API base URL
	configuration    config.Configuration              //The configuration structure
	forwardServerUrl string                            //The URL the requests should be forwarded to
	checkers         []code.IValidator                 //The list of validators which will be run on the request and the response to find malicious activity
	rules            []rules.Rule                      //The list of rules which will try to find anomalies in the requests and the responses
	apiWsConn        *websocket.APIWebSocketConnection //The WS connection to the API
	targetWsConn     *ws_gorilla.Conn                  //The websocket connection to the target server
}

func NewBlueberryWebsocketHandler(logger logging.ILogger, apiBaseURL string, configuration config.Configuration, forwardServerURL string, checkers []code.IValidator, rules []rules.Rule, apiWsConn *websocket.APIWebSocketConnection) *BlueberryWebsocketHandler {
	return &BlueberryWebsocketHandler{
		logger:           logger,
		apiBaseURL:       apiBaseURL,
		configuration:    configuration,
		forwardServerUrl: forwardServerURL,
		checkers:         checkers,
		rules:            rules,
		apiWsConn:        apiWsConn,
	}
}

func (bwsh *BlueberryWebsocketHandler) ConnectToTargetServer() error {
	//Parse the forward server URL
	target_url, err := url.Parse(bwsh.forwardServerUrl)
	//Check if an error occured
	if err != nil {
		bwsh.logger.Error("Failed to parse target server url", err.Error())
		return err
	}

	//Create the websocket url for the backend server
	ws_url := fmt.Sprintf("%s://%s/%s", "ws", target_url.Host, target_url.RawPath)

	bwsh.logger.Debug("Backend websocket URL", ws_url)

	//Connect to the websocket backend
	backendConn, _, err := ws_gorilla.DefaultDialer.Dial(ws_url, nil)
	if err != nil {
		bwsh.logger.Error("Failed to connect to backend websocket server")
		return err
	}

	//Save the backend connection in the struct
	bwsh.targetWsConn = backendConn

	return nil
}

func (bwsh *BlueberryWebsocketHandler) ProxyRequests(clientConn *ws_gorilla.Conn, errc chan error) {
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(bwsh.logger, bwsh.rules, bwsh.apiWsConn, bwsh.configuration)

	for {
		mt, message, err := clientConn.ReadMessage()
		if err != nil {
			bwsh.logger.Error("Failed to read websocket message from client", clientConn.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//Apply the rules on the websocket messages
		//TODO...Add direction to the websocket rules
		findings, err := ruleRunner.RunRulesOnWebsocketMessage(mt, message)
		if err != nil {
			bwsh.logger.Error("Error when running rules on websocket message", err.Error())
		}
		bwsh.logger.Debug("Websocket client -> backend server findings", findings)

		//Get the verdict based on the findings
		verdict := rules.GetVerdictBasedOnFindings(bwsh.rules, bwsh.configuration.RuleConfig.DefaultAction, findings)

		if verdict == "drop" {
			//Create forbidden json
			forbiddenJson := fmt.Sprintf("{\"message\":\"%s\"}", bwsh.configuration.RuleConfig.ForbiddenTCPMessage)
			//Send the forbidden message back to the client
			err := clientConn.WriteMessage(ws_gorilla.TextMessage, []byte(forbiddenJson))
			//Check for errors
			if err != nil {
				bwsh.logger.Error("Failed to send forbidden message to client", clientConn.RemoteAddr().String(), err.Error())
			}
			continue
		}

		//TODO...Send findings to the API

		//Send the request to target websocket server

		err = bwsh.targetWsConn.WriteMessage(mt, message)
		if err != nil {
			bwsh.logger.Error("Failed to send message to target websocket server", err.Error())
			errc <- err
			return
		}
	}
}

func (bwsh *BlueberryWebsocketHandler) ProxyResponses(clientConn *ws_gorilla.Conn, errc chan error) {
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(bwsh.logger, bwsh.rules, bwsh.apiWsConn, bwsh.configuration)

	for {
		mt, message, err := bwsh.targetWsConn.ReadMessage()
		if err != nil {
			bwsh.logger.Error("Failed to read websocket message from target server", bwsh.targetWsConn.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//Apply the rules on the websocket messages
		//TODO...Add direction to the websocket rules
		findings, err := ruleRunner.RunRulesOnWebsocketMessage(mt, message)
		if err != nil {
			bwsh.logger.Error("Error when running rules on websocket message", err.Error())
		}
		bwsh.logger.Debug("Backend server -> websocket client findings", findings)

		//Get the verdict based on the findings
		verdict := rules.GetVerdictBasedOnFindings(bwsh.rules, bwsh.configuration.RuleConfig.DefaultAction, findings)

		if verdict == "drop" {
			//Create forbidden json
			forbiddenJson := fmt.Sprintf("{\"message\":\"%s\"}", bwsh.configuration.RuleConfig.ForbiddenTCPMessage)
			//Send the forbidden message back to the client
			err := clientConn.WriteMessage(ws_gorilla.TextMessage, []byte(forbiddenJson))
			//Check for errors
			if err != nil {
				bwsh.logger.Error("Failed to send forbidden message to client", clientConn.RemoteAddr().String(), err.Error())
			}
			continue
		}

		//TODO...Send findings to the API

		//Send the request to target websocket server

		err = clientConn.WriteMessage(mt, message)
		if err != nil {
			bwsh.logger.Error("Failed to send message to target websocket server", err.Error())
			errc <- err
			return
		}
	}
}

// Handle websocket messages
func (bwsh *BlueberryWebsocketHandler) HandleWebsocketConnection(rw http.ResponseWriter, r *http.Request) {
	//Connect to target websocket server
	err := bwsh.ConnectToTargetServer()
	if err != nil {
		bwsh.logger.Error("Failed to connect to target websocket server", err.Error())
		return
	}
	defer bwsh.targetWsConn.Close()

	// Upgrade incoming HTTP request to WebSocket
	clientConn, err := upgrader.Upgrade(rw, r, nil)
	if err != nil {
		bwsh.logger.Error("Failed to upgrade client connection", err.Error(), clientConn.RemoteAddr().String())
		return
	}
	defer clientConn.Close()

	bwsh.logger.Debug("Upgraded client connection to websocket connection", clientConn.RemoteAddr().String())

	// Proxy messages between client and backend
	errc := make(chan error, 2)

	//Proxy messages from client to the backend web server
	go bwsh.ProxyRequests(clientConn, errc)

	//Proxy messages from the backend web server to the client
	go bwsh.ProxyResponses(clientConn, errc)

	<-errc // wait for first error or disconnect
}
