package handlers

import (
	"blueberry/internal/config"
	"blueberry/internal/cranberry"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/logging"
	"blueberry/internal/models"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
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

// Structure which holds information about the client connection
type ClientConnection struct {
	clientSocket            net.Conn   //The socket to interact with the client
	clientSocketMutex       sync.Mutex //The mutex for the client connection socket
	streamUUID              string     //The UUID of the stream so that the client connection can be identified from logs
	currentStreamIndex      int64      //The current index to be used by request/response traffic
	currentStreamIndexMutex sync.Mutex //The mutex for the current stream index (prevent race conditions)
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
func (bth *BlueberryTCPHandler) ProxyRequests(clientConn *ClientConnection, errc chan error) {
	//Create the buffer
	buf := make([]byte, DefaultBufferSize)

	//TODO...Add timeout to read

	//Initialize the rules runner
	ruleRunner := rules.NewRuleRunner(bth.logger, bth.rules, bth.apiWsConn, bth.configuration)

	//Infinite loop
	for {
		//Read from the client connection max DefaultBufferSize bytes
		readBytes, err := clientConn.clientSocket.Read(buf)
		if err != nil {
			//Log the error
			bth.logger.Error("Failed to read message from client", clientConn.clientSocket.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//Make the buffer the correct size
		buf = buf[:readBytes]
		bth.logger.Debug("Received tcp message from", clientConn.clientSocket.RemoteAddr().String(), "content", string(buf))

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
			_, err := clientConn.clientSocket.Write([]byte(bth.configuration.RuleConfig.ForbiddenTCPMessage))
			if err != nil {
				bth.logger.Error("Failed to send forbidden message to", clientConn.clientSocket.RemoteAddr().String(), err.Error())
			}
		}

		//Send the ingress log to server and increment the stream index
		//Initialize the log data
		remoteIp, _, _ := net.SplitHostPort(clientConn.clientSocket.RemoteAddr().String())
		logData := models.LogData{
			AgentId:         bth.configuration.UUID,
			RemoteIP:        remoteIp,
			Timestamp:       time.Now().Unix(),
			StreamUUID:      clientConn.streamUUID,
			RequestFindings: findings,
			Verdict:         verdict,
			Type:            "tcp",
			Direction:       "ingress",
		}

		//Convert the buf with ingress data to base64 and add to log data Request field
		logData.Request = utils.ConvertBytesToBase64(buf)

		//Lock the stream mutex
		clientConn.currentStreamIndexMutex.Lock()
		//Use the current stream index
		logData.StreamIndex = clientConn.currentStreamIndex
		//Increment the stream index
		clientConn.currentStreamIndex += 1
		//Unlock the stream mutex
		clientConn.currentStreamIndexMutex.Unlock()

		cClient := cranberry.NewCranberryClient(bth.logger, bth.configuration)
		_, err = cClient.SendLog(logData)
		if err != nil {
			bth.logger.Error("Failed to send log data to cranberry", err.Error())
		}

		//If verdict is drop then continue to next request
		if verdict == "drop" {
			continue
		}

		//Write the buffer to the target server
		_, err = bth.targetTcpServer.Write(buf)
		if err != nil {
			bth.logger.Error("Failed to write message to target server", clientConn.clientSocket.RemoteAddr().String(), err.Error())
			errc <- err
			return
		}

		//TODO...Check if the number of written bytes is the same as read bytes
	}
}

// This connection will proxy the traffic from target server back to the client
// @param clientConn - the connection from the client
// @param errc - the channel for errors
func (bth *BlueberryTCPHandler) ProxyResponses(clientConn *ClientConnection, errc chan error) {
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
			_, err := clientConn.clientSocket.Write([]byte(bth.configuration.RuleConfig.ForbiddenTCPMessage))
			if err != nil {
				bth.logger.Error("Failed to send forbidden message to", clientConn.clientSocket.RemoteAddr().String(), err.Error())
			}
		}

		//Send the egress log to server and increment the stream index
		//Initialize the log data
		remoteIp, _, _ := net.SplitHostPort(clientConn.clientSocket.RemoteAddr().String())
		logData := models.LogData{
			AgentId:          bth.configuration.UUID,
			RemoteIP:         remoteIp,
			Timestamp:        time.Now().Unix(),
			StreamUUID:       clientConn.streamUUID,
			ResponseFindings: findings,
			Verdict:          verdict,
			Type:             "tcp",
			Direction:        "egress",
		}

		//Convert the buf with ingress data to base64 and add to log data Request field
		logData.Response = utils.ConvertBytesToBase64(buf)

		//Lock the stream mutex
		clientConn.currentStreamIndexMutex.Lock()
		//Use the current stream index
		logData.StreamIndex = clientConn.currentStreamIndex
		//Increment the stream index
		clientConn.currentStreamIndex += 1
		//Unlock the stream mutex
		clientConn.currentStreamIndexMutex.Unlock()

		cClient := cranberry.NewCranberryClient(bth.logger, bth.configuration)
		_, err = cClient.SendLog(logData)
		if err != nil {
			bth.logger.Error("Failed to send log data to cranberry", err.Error())
		}

		//If the verdict is drop then continue to next response
		if verdict == "drop" {
			continue
		}

		//Write the buffer to the target server
		_, err = clientConn.clientSocket.Write(buf)
		if err != nil {
			bth.logger.Error("Failed to write message to from target server to client", clientConn.clientSocket.RemoteAddr().String(), err.Error())
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

	//Create the structure for the client connection
	//Generate a new UUID
	clientConn := ClientConnection{clientSocket: conn, streamUUID: uuid.New().String(), currentStreamIndex: 0}

	//Proxy the traffic from the conn in the function parameters and the target connection
	//Proxy the requests
	go bth.ProxyRequests(&clientConn, errc)
	//Proxy the responses
	go bth.ProxyResponses(&clientConn, errc)

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
