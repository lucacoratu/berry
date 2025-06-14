package handlers

import (
	"blueberry/internal/config"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/logging"
	"blueberry/internal/websocket"
	"net"
	"net/url"
	"sync"
)

// Buffer size for the TCP connections
const (
	DefaultBufferSize = 8192
)

// Structure which holds all the necessary variables for TCP handler
type BlueberryTCPHandler struct {
	logger           logging.ILogger
	apiBaseURL       string                            //The API base URL
	configuration    config.Configuration              //The configuration structure
	forwardServerUrl string                            //The URL the requests should be forwarded to
	checkers         []code.IValidator                 //The list of validators which will be run on the request and the response to find malicious activity
	rules            []rules.Rule                      //The list of rules which will try to find anomalies in the requests and the responses
	apiWsConn        *websocket.APIWebSocketConnection //The WS connection to the API
	//TODO add global mutex for api websocket connection
	targetTcpServer net.Conn
	targetTcpMutex  sync.Mutex
}

func NewBlueberryTCPHandler(logger logging.ILogger, apiBaseURL string, configuration config.Configuration, forwardServerURL string, checkers []code.IValidator, rules []rules.Rule, apiWsConn *websocket.APIWebSocketConnection) *BlueberryTCPHandler {
	return &BlueberryTCPHandler{
		logger:           logger,
		apiBaseURL:       apiBaseURL,
		configuration:    configuration,
		forwardServerUrl: forwardServerURL,
		checkers:         checkers,
		rules:            rules,
		apiWsConn:        apiWsConn,
	}
}

func (bth *BlueberryTCPHandler) ConnectToTargetServer() error {
	//Parse the URL
	url, err := url.Parse(bth.forwardServerUrl)
	if err != nil {
		bth.logger.Error("Failed to parse forward server url", err.Error())
		return err
	}

	//Get the host and the port from the url
	serverAddress := url.Host

	//Resolve TCP address of the target server
	tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddress)
	if err != nil {
		bth.logger.Error("Failed to resolve address for forward server", err.Error())
		return err
	}

	//Dial the server
	targetConn, err := net.DialTCP(url.Scheme, nil, tcpAddr)
	if err != nil {
		bth.logger.Error("Failed to dial target tcp server", err.Error())
		return err
	}

	//Save the target connection in the handler struct
	bth.targetTcpServer = targetConn

	return nil
}

// This function will proxy the traffic from client to target server
// @param clientConn - the connection from the client
// @param errc - the channel where any error will be sent so that the connection wil be closed
func (bth *BlueberryTCPHandler) ProxyRequests(clientConn net.Conn, errc chan error) {
	//Create the buffer
	buf := make([]byte, DefaultBufferSize)

	//TODO...Add timeout to read

	//Initialize the rules runner
	ruleRunner := rules.NewRuleRunner(bth.logger, bth.rules, bth.apiWsConn, bth.configuration)

	//Infinite loop
	for {
		//Read from the client connection max DefaultBufferSize bytes
		readBytes, err := clientConn.Read(buf)
		if err != nil {
			//Log the error
			bth.logger.Error("Failed to read message from client", clientConn.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//Make the buffer the correct size
		buf = buf[:readBytes]
		bth.logger.Debug("Received tcp message from", clientConn.RemoteAddr().String(), "content", string(buf))

		//Apply the tcp request rules
		findings, err := ruleRunner.ApplyRulesOnTCPMessage("ingress", buf)
		if err != nil {
			bth.logger.Warning("Failed to apply rules on ingress TCP message", err.Error())
		}
		bth.logger.Debug("Ingress findings", findings)

		//Get the verdict based on findings
		verdict := rules.GetVerdictBasedOnFindings(bth.rules, bth.configuration.RuleConfig.DefaultAction, findings)
		if verdict == "drop" {
			//Send the drop message for tcp connection
			_, err := clientConn.Write([]byte(bth.configuration.RuleConfig.ForbiddenTCPMessage))
			if err != nil {
				bth.logger.Error("Failed to send forbidden message to", clientConn.RemoteAddr().String(), err.Error())
			}
			//Continue to next read (protect target server)
			continue
		}

		//Write the buffer to the target server
		_, err = bth.targetTcpServer.Write(buf)
		if err != nil {
			bth.logger.Error("Failed to write message to target server", clientConn.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//TODO...Check if the number of written bytes is the same as read bytes
	}
}

// This connection will proxy the traffic from target server back to the client
// @param clientConn - the connection from the client
// @param errc - the channel for errors
func (bth *BlueberryTCPHandler) ProxyResponses(clientConn net.Conn, errc chan error) {
	//Create the buffer
	buf := make([]byte, DefaultBufferSize)

	//TODO...Add timeout to read

	//Initialize the rules runner
	ruleRunner := rules.NewRuleRunner(bth.logger, bth.rules, bth.apiWsConn, bth.configuration)

	//Infinite loop
	for {
		//Read from the client connection max DefaultBufferSize bytes
		readBytes, err := bth.targetTcpServer.Read(buf)
		if err != nil {
			//Log the error
			bth.logger.Error("Failed to read message from target server", err.Error())
			errc <- err
			return
		}

		//Make the buffer the correct size
		buf = buf[:readBytes]
		bth.logger.Debug("Received tcp message from target server, content", string(buf))

		//Apply the response tcp rules
		findings, err := ruleRunner.ApplyRulesOnTCPMessage("egress", buf)
		if err != nil {
			bth.logger.Error("Failed to apply rules on egress TCP message", err.Error())
		}
		bth.logger.Debug("Egress findings", findings)

		//Get the verdict based on findings
		verdict := rules.GetVerdictBasedOnFindings(bth.rules, bth.configuration.RuleConfig.DefaultAction, findings)
		if verdict == "drop" {
			//Send the drop message for tcp connection
			_, err := clientConn.Write([]byte(bth.configuration.RuleConfig.ForbiddenTCPMessage))
			if err != nil {
				bth.logger.Error("Failed to send forbidden message to", clientConn.RemoteAddr().String(), err.Error())
			}
			//Continue to next read (the message has been sent to client)
			continue
		}

		//Write the buffer to the target server
		_, err = clientConn.Write(buf)
		if err != nil {
			bth.logger.Error("Failed to write message to from target server to client", clientConn.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//TODO...Check if the number of written bytes is the same as read bytes
	}
}

// Handle TCP connection
func (bth *BlueberryTCPHandler) HandleTCPConnection(conn net.Conn) {
	//Connect to the target tcp server
	err := bth.ConnectToTargetServer()
	//Check if the connection failed
	if err != nil {
		//Log the error
		bth.logger.Error("Failed to connect to target server", err.Error())
		//Close the connection that needs to be handled
		err = conn.Close()
		if err != nil {
			bth.logger.Error("Failed when calling close on connection", conn.RemoteAddr().String(), err.Error())
		}
		//Return from function
		return
	}

	//Create the error channel
	//This will receive error from either the client or the target server and the connection will be closed
	errc := make(chan error, 2)

	//Proxy the traffic from the conn in the function parameters and the target connection
	//Proxy the requests
	go bth.ProxyRequests(conn, errc)
	//Proxy the responses
	go bth.ProxyResponses(conn, errc)

	//Wait for errors
	<-errc

	//Close the client connection
	err = conn.Close()
	if err != nil {
		bth.logger.Error("Failed when calling close on connection", conn.RemoteAddr().String(), err.Error())
	}

	//Close the connection to the target server
	err = bth.targetTcpServer.Close()
	if err != nil {
		bth.logger.Error("Failed to close connection to the target server", err.Error())
	}
}
