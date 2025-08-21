package handlers

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	ws_gorilla "github.com/gorilla/websocket"

	"blueberry/internal/config"
	"blueberry/internal/cranberry"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/logging"
	"blueberry/internal/models"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
)

/*
 * Structure which holds all the information needed by the handler for the HTTP requests
 */
type BlueberryHTTPHandler struct {
	logger           logging.ILogger                   //The logger interface
	apiBaseURL       string                            //The API base URL
	configuration    config.Configuration              //The configuration structure
	forwardServerUrl string                            //The URL the requests should be forwarded to
	checkers         []code.IValidator                 //The list of validators which will be run on the request and the response to find malicious activity
	rules            []rules.Rule                      //The list of rules which will try to find anomalies in the requests and the responses
	apiWsConn        *websocket.APIWebSocketConnection //The WS connection to the API
}

// Creates a new BlueberryHandlerStructure
func NewBlueberryHTTPHandler(logger logging.ILogger, apiBaseURL string, configuration config.Configuration, forwardServerUrl string, checkers []code.IValidator, rules []rules.Rule, apiWsConn *websocket.APIWebSocketConnection) *BlueberryHTTPHandler {
	return &BlueberryHTTPHandler{logger: logger, apiBaseURL: apiBaseURL, configuration: configuration, forwardServerUrl: forwardServerUrl, checkers: checkers, rules: rules, apiWsConn: apiWsConn}
}

// Forwards the request to the target server
func (bHandler *BlueberryHTTPHandler) forwardRequest(req *http.Request) (*http.Response, error) {
	// we need to buffer the body if we want to read it here and send it
	// in the request.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, errors.New("could not send the request to the target web server, " + err.Error())
	}

	// you can reassign the body if you need to parse it as multipart
	req.Body = io.NopCloser(bytes.NewReader(body))

	proxyReq, err := http.NewRequest(req.Method, bHandler.forwardServerUrl, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("could not create the new request to forward to target web server")
	}

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	//Create a client which will not follow rediects
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		return nil, errors.New("could not send the request to the target web server, " + err.Error())
	}

	bHandler.logger.Debug("Forward request, response status code", resp.StatusCode)

	return resp, nil
}

// Forwards the response back to the client
func (bHandler *BlueberryHTTPHandler) forwardResponse(rw http.ResponseWriter, response *http.Response) {
	//Send the headers
	for name, values := range response.Header {
		val := ""
		for _, value := range values {
			val += value
			if len(values) > 1 {
				val += ";"
			}
		}
		rw.Header().Set(name, val)
	}
	//Send the status code
	bHandler.logger.Debug(response.Status)
	rw.WriteHeader(response.StatusCode)

	//Send the body
	body, err := io.ReadAll(response.Body)
	//agent.logger.Debug("Body:", body)

	if err != nil {
		rw.Write([]byte("error"))
		return
	}
	rw.Write(body)
}

// Upgrader for the websocket
var upgrader = ws_gorilla.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins, modify as needed
	},
}

// Handles the requests received by the agent
func (bHandler *BlueberryHTTPHandler) HandleRequest(rw http.ResponseWriter, r *http.Request) {
	//Check if the request is a websocket upgrade
	if ws_gorilla.IsWebSocketUpgrade(r) {
		//Create the websocket handler
		wsHandler := NewBlueberryWebsocketHandler(
			bHandler.logger,
			bHandler.apiBaseURL,
			bHandler.configuration,
			bHandler.forwardServerUrl,
			bHandler.checkers,
			bHandler.rules,
			bHandler.apiWsConn,
		)

		bHandler.logger.Debug("Websocket upgrade message received from", r.RemoteAddr)

		//Handle the websocket connection separately
		wsHandler.HandleWebsocketConnection(rw, r)

		//Return from the function
		return
	}

	//Initialize the cranberry client
	cClient := cranberry.NewCranberryClient(bHandler.logger, bHandler.configuration)

	//Create the log data
	remoteIp, _, _ := net.SplitHostPort(r.RemoteAddr)
	logData := models.LogData{AgentId: bHandler.configuration.UUID, RemoteIP: remoteIp, Timestamp: time.Now().Unix(), Type: "http"}

	//Log the endpoint where the request was made
	bHandler.logger.Info("Received", r.Method, "request on", r.URL.Path)

	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(bHandler.logger, bHandler.rules, bHandler.apiWsConn, bHandler.configuration)

	//Run all the rules on the request
	startTime := time.Now()
	requestRuleFindings, _ := ruleRunner.RunRulesOnRequest(r)
	endTime := time.Now()

	bHandler.logger.Debug("Applied", len(bHandler.rules), "rules on request in", float64(endTime.UnixNano()-startTime.UnixNano())/float64(1000000), "ms")

	//Log the request rule findings
	bHandler.logger.Debug("Request rule findings", requestRuleFindings)

	//Add the request rule findings to the log data
	logData.RequestFindings = requestRuleFindings

	//Get the verdict based on the findings
	verdict := rules.GetVerdictBasedOnFindings(bHandler.rules, bHandler.configuration.RuleConfig.DefaultAction, requestRuleFindings)

	//Add the request findings and the request raw dump
	b64Req, err := utils.ConvertRequestToB64(r)
	if err != nil {
		bHandler.logger.Error("Failed to dump request to raw data and convert to base64", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal error"))
		return
	}

	logData.Request = b64Req

	//If the verdict is drop then send the forbidden page back to the client
	if verdict == "drop" {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte(bHandler.configuration.RuleConfig.ForbiddenHTTPMessage))
		logData.Verdict = "drop"
		newResp, err := utils.GetEncodedForbiddenMessage(bHandler.configuration.RuleConfig.ForbiddenHTTPMessage)
		if err != nil {
			bHandler.logger.Warning("Failed to get base64 encoded response", err.Error(), "will default to empty response")
		} else {
			logData.Response = newResp
		}
		cClient.SendLog(logData)
		return
	}

	//Forward the request to the destination web server
	response, err := bHandler.forwardRequest(r)
	if err != nil {
		bHandler.logger.Error(err.Error())
		//TO DO...Send a error message back to the client
		return
	}

	//Run the rules on the response
	responseRuleFindings, _ := ruleRunner.RunRulesOnResponse(response)

	//Log the rules response findings
	bHandler.logger.Debug("Response rule findings", responseRuleFindings)

	//Add the response findings to the list response findings
	logData.ResponseFindings = responseRuleFindings

	//Get the verdict for the response
	verdictResponse := rules.GetVerdictBasedOnFindings(bHandler.rules, bHandler.configuration.RuleConfig.DefaultAction, responseRuleFindings)

	//Add the response to the log data
	b64Resp, err := utils.ConvertResponseToB64(response)
	if err != nil {
		bHandler.logger.Error("Failed to dump response to raw data and convert to base64", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal error"))
		return
	}

	logData.Response = b64Resp

	//If the verdict is drop then send the forbidden http message
	if verdictResponse == "drop" {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte(bHandler.configuration.RuleConfig.ForbiddenHTTPMessage))
		logData.Verdict = "drop"
		//TODO...Add the forbidden response
		cClient.SendLog(logData)
		return
	}

	//This is for the case the request is legitimate
	logData.Verdict = "allow"
	cClient.SendLog(logData)

	//Send the response from the web server back to the client
	bHandler.forwardResponse(rw, response)
}
