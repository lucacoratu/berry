package handlers

import (
	"bytes"
	"encoding/base64"
	b64 "encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	ws_gorilla "github.com/gorilla/websocket"

	"blueberry/internal/config"
	api "blueberry/internal/cranberry"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	data "blueberry/internal/models"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
	"blueberry/pkg/logging"
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

// Combines the request and response findings into a single slice
func (bHandler *BlueberryHTTPHandler) combineFindings(requestFindings []data.FindingData, responseFindings []data.FindingData) []data.Finding {
	//Add all the findings from all the validators to a list which will be sent to the API
	allFindings := make([]data.Finding, 0)
	//Add all request findings
	for index, finding := range requestFindings {
		if index < len(responseFindings) {
			allFindings = append(allFindings, data.Finding{Request: finding, Response: responseFindings[index]})
		} else {
			allFindings = append(allFindings, data.Finding{Request: finding, Response: data.FindingData{}})
		}
	}

	//Add the response findings
	for index, finding := range responseFindings {
		//If the index is less than the length of the all findings list then complete the index structure with the response findings
		if index < len(allFindings) {
			allFindings[index].Response = finding
		} else {
			//Otherwise add a new structure to the list of all findings which will have the Request empty
			allFindings = append(allFindings, data.Finding{Request: data.FindingData{}, Response: finding})
		}
	}

	return allFindings
}

func (bHandler *BlueberryHTTPHandler) combineRuleFindings(requestRuleFindings []*data.RuleFindingData, responseRuleFindings []*data.RuleFindingData) []data.RuleFinding {
	//Add all the findings from all the validators to a list which will be sent to the API
	allFindings := make([]data.RuleFinding, 0)
	//Add all request findings
	for index, finding := range requestRuleFindings {
		if index < len(responseRuleFindings) {
			allFindings = append(allFindings, data.RuleFinding{Request: finding, Response: responseRuleFindings[index]})
		} else {
			allFindings = append(allFindings, data.RuleFinding{Request: finding, Response: nil})
		}
	}

	//Add the response findings
	for index, finding := range responseRuleFindings {
		//If the index is less than the length of the all findings list then complete the index structure with the response findings
		if index < len(allFindings) {
			allFindings[index].Response = finding
		} else {
			//Otherwise add a new structure to the list of all findings which will have the Request empty
			allFindings = append(allFindings, data.RuleFinding{Request: nil, Response: finding})
		}
	}

	return allFindings
}

// Converts the response to raw string then base64 encodes it
func (bHandler *BlueberryHTTPHandler) convertRequestToB64(req *http.Request) (string, error) {
	//Dump the HTTP request to raw string
	rawRequest, err := utils.DumpHTTPRequest(req)
	//Check if an error occured when dumping the request as raw string
	if err != nil {
		bHandler.logger.Error(err.Error())
		return "", err
	}
	//Convert raw request to base64
	b64RawRequest := b64.StdEncoding.EncodeToString(rawRequest)
	//Return the base64 string of the request and the response
	return b64RawRequest, nil
}

// Converts the request and the response to raw string then base64 encodes both of them
func (bHandler *BlueberryHTTPHandler) convertRequestAndResponseToB64(req *http.Request, resp *http.Response) (string, string, error) {
	//Dump the HTTP request to raw string
	rawRequest, _ := utils.DumpHTTPRequest(req)
	//Dump the response as raw string
	rawResponse, err := utils.DumpHTTPResponse(resp)
	//Check if an error occured when dumping the response as raw string
	if err != nil {
		bHandler.logger.Error(err.Error())
		return "", "", err
	}
	//Convert raw request to base64
	b64RawRequest := b64.StdEncoding.EncodeToString(rawRequest)
	//Convert raw response to base64
	b64RawResponse := b64.StdEncoding.EncodeToString(rawResponse)
	//Return the base64 string of the request and the response
	return b64RawRequest, b64RawResponse, nil
}

// Handle the request if the agent is running in waf operation mode
// @param requestFindings the code findings after checking the request
// @param requestRuleFindings the findings after applying the rules on the request
// Returns bool (true if the request should be dropped, false if should be allowed)
// Returns error if an error occured during the handling of findings
func (bHandler *BlueberryHTTPHandler) HandleWAFOperationModeOnRequest(requestFindings []data.FindingData, requestRuleFindings []*data.RuleFindingData) (bool, error) {
	//Loop through all the code findings

	//Loop through all the rules findings
	for _, ruleFinding := range requestRuleFindings {
		//Get the id of the rule
		ruleAction := rules.GetRuleAction(bHandler.rules, ruleFinding.RuleId)
		//Check if the rule action is drop
		//If the rule action is empty the default behavior should be to drop
		if ruleAction == "drop" || ruleAction == "" {
			//The request should be blocked
			return true, nil
		}
	}

	//The request shouldn't be blocked
	return false, nil
}

// Handle the response in waf operation mode
// @param responseFindings the code findings after checking the request
// @param responseRuleFindings the findings after applying the rules on the request
// Returns bool (true if the request should be dropped, false if should be allowed)
// Returns error if an error occured during the handling of findings
func (bHandler *BlueberryHTTPHandler) HandleWAFOperationModeOnResponse(responseFindings []data.FindingData, responseRuleFindings []*data.RuleFindingData) (bool, error) {
	//Loop through all the code findings

	//Loop through all the rules findings
	for _, ruleFinding := range responseRuleFindings {
		//Get the id of the rule
		ruleAction := rules.GetRuleAction(bHandler.rules, ruleFinding.RuleId)
		//Check if the rule action is drop
		//If the rule action is empty the default behavior should be to drop
		if ruleAction == "drop" || ruleAction == "" {
			//The request should be blocked
			return true, nil
		}
	}

	return false, nil
}

// Upgrader for the websocket
var upgrader = ws_gorilla.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins, modify as needed
	},
}

// Handle websocket messages
func (bHandler *BlueberryHTTPHandler) HandleWebsocketConnection(rw http.ResponseWriter, r *http.Request) {
	// Upgrade incoming HTTP request to WebSocket
	clientConn, err := upgrader.Upgrade(rw, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer clientConn.Close()

	bHandler.logger.Debug("Upgraded to websocket connection")

	// Dial to target backend WebSocket server
	backendConn, _, err := ws_gorilla.DefaultDialer.Dial(bHandler.forwardServerUrl, nil)
	if err != nil {
		log.Println("Dial error:", err)
		return
	}
	defer backendConn.Close()

	// Proxy messages between client and backend
	errc := make(chan error, 2)

	//Proxy messages from client to the backend web server
	go bHandler.proxyWS(clientConn, backendConn, errc)
	//Proxy messages from the backend web server to the client
	go bHandler.proxyWS(backendConn, clientConn, errc)

	<-errc // wait for first error or disconnect
}

func (bHandler *BlueberryHTTPHandler) proxyWS(src, dest *ws_gorilla.Conn, errc chan error) {
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(bHandler.logger, bHandler.rules, bHandler.apiWsConn, bHandler.configuration)

	for {
		mt, message, err := src.ReadMessage()
		if err != nil {
			bHandler.logger.Error("Websocket connection closed,", err.Error())
			errc <- err
			return
		}

		//Apply the rules on the websocket messages
		findings, err := ruleRunner.RunRulesOnWebsocketMessage(mt, message)
		if err != nil {
			bHandler.logger.Error("Error when running rules on websocket message", err.Error())
		}
		bHandler.logger.Debug(findings)

		//Convert the request to base64
		b64RawRequest := b64.StdEncoding.EncodeToString(message)

		//Initialize the request should be blocked variable
		var requestBlocked bool = false

		//Add all the findings from all the validators to a list which will be sent to the API
		allFindings := make([]data.RuleFinding, 0)
		//Add all request findings
		for _, finding := range findings {
			allFindings = append(allFindings, data.RuleFinding{Request: finding, Response: nil})

			//Check if operation mode of the agent is waf
			if bHandler.configuration.OperationMode == "waf" {
				rule_action := rules.GetRuleAction(bHandler.rules, finding.RuleId)
				if rule_action == "drop" || rule_action == "" {
					requestBlocked = true
				}
			}
		}

		//Initialize the forbidden message
		forbiddenMessage := []byte("{\"status_code\": 403, \"message\": \"Forbidden, you do not have permissions to access this resource\"}")

		//Create the log structure that should be sent to the API
		logData := data.LogData{AgentId: bHandler.configuration.UUID, RemoteIP: src.NetConn().RemoteAddr().String(), Timestamp: time.Now().Unix(), Websocket: true, Request: b64RawRequest, Response: "", Findings: nil, RuleFindings: allFindings}

		//If the request is blocked then add the forbidden message as response in the log data
		if requestBlocked {
			logData.Response = b64.StdEncoding.EncodeToString(forbiddenMessage)
		}

		bHandler.logger.Debug("Log data", logData)

		//Send the findings to the API
		if bHandler.apiWsConn != nil {
			//Send log information to the API
			apiHandler := api.NewAPIHandler(bHandler.logger, bHandler.configuration)
			_, err = apiHandler.SendLog(bHandler.apiBaseURL, logData)
			//Check if an error occured when sending log to the API
			if err != nil {
				bHandler.logger.Error(err.Error())
				//return
			}
		}

		//If the request is blocked
		if requestBlocked {
			src.WriteMessage(ws_gorilla.TextMessage, forbiddenMessage)
		}

		if !requestBlocked {
			err = dest.WriteMessage(mt, message)
			if err != nil {
				bHandler.logger.Error("Websocket connection closed,", err.Error())
				errc <- err
				return
			}
		}
	}
}

// Handles the requests received by the agent
func (bHandler *BlueberryHTTPHandler) HandleRequest(rw http.ResponseWriter, r *http.Request) {
	//Check if the request is a websocket upgrade
	if ws_gorilla.IsWebSocketUpgrade(r) {
		bHandler.logger.Debug("Websocket upgrade message received")
		//Handle the websocket connection separately
		bHandler.HandleWebsocketConnection(rw, r)
		//Return from the function
		return
	}

	//Log the endpoint where the request was made
	bHandler.logger.Info("Received", r.Method, "request on", r.URL.Path)

	//Create the validator runner
	validatorRunner := code.NewValidatorRunner(bHandler.checkers, bHandler.logger)
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(bHandler.logger, bHandler.rules, bHandler.apiWsConn, bHandler.configuration)

	//Run all the validators on the request
	requestFindings, _ := validatorRunner.RunValidatorsOnRequest(r)
	//Run all the rules on the request
	startTime := time.Now()
	requestRuleFindings, _ := ruleRunner.RunRulesOnRequest(r)
	endTime := time.Now()
	bHandler.logger.Debug("Applied rules on request in", float64(endTime.UnixNano()-startTime.UnixNano())/float64(1000000), "ms")

	//Log request findings
	bHandler.logger.Debug("Request findings", requestFindings)
	//Log the request rule findings
	bHandler.logger.Debug("Request rule findings", requestRuleFindings)

	//If the mode of operation is waf check the action from the rule
	//If the action specified inside the rule is block then the forbidden page should be sent to the client
	var requestDropped bool = false
	var err error = nil

	//Check if the operation mode is waf and the forbidden page has been returned
	//If the forbidden page has been returned then the request should not be forwarded to the target service
	//Also the rules and validators shouldn't be applied on response (as it will always be the forbidden page)
	if bHandler.configuration.OperationMode == "waf" {
		requestDropped, err = bHandler.HandleWAFOperationModeOnRequest(requestFindings, requestRuleFindings)
		if err != nil {
			bHandler.logger.Error("Error occured when handling waf operation mode on request", err.Error())
		}
	}

	var response *http.Response = nil
	var responseFindings []data.FindingData = make([]data.FindingData, 0)
	var responseRuleFindings []*data.RuleFindingData = make([]*data.RuleFindingData, 0)

	//Initialize the response dropped
	var responseDropped bool = false

	if !requestDropped || bHandler.configuration.OperationMode != "waf" {
		//Forward the request to the destination web server
		response, err = bHandler.forwardRequest(r)
		if err != nil {
			bHandler.logger.Error(err.Error())
			return
		}

		//Run the validators on the response
		responseFindings, _ = validatorRunner.RunValidatorsOnResponse(response)
		//Run the rules on the response
		responseRuleFindings, _ = ruleRunner.RunRulesOnResponse(response)

		//Log response findings
		bHandler.logger.Debug("Response findings", responseFindings)
		//Log the rules response findings
		bHandler.logger.Debug("Response rule findings", responseRuleFindings)

		//Check if the response should be dropped
		responseDropped, err = bHandler.HandleWAFOperationModeOnResponse(responseFindings, responseRuleFindings)
		if err != nil {
			bHandler.logger.Error("Error occured when handling waf operation mode on request", err.Error())
		}
	}

	//Combine the findings into a single structure
	//If the request is not forwarded then the response findings should be empty arrays
	allFindings := bHandler.combineFindings(requestFindings, responseFindings)
	//Combine the rule findings into a single structure
	allRuleFindings := bHandler.combineRuleFindings(requestRuleFindings, responseRuleFindings)

	//Convert the request and response to base64 string
	//If the response is nil (the request was dropped then convert the forbidden page to base64)
	var b64RawRequest string = ""
	var b64RawResponse string = ""
	if !requestDropped {
		b64RawRequest, b64RawResponse, _ = bHandler.convertRequestAndResponseToB64(r, response)
	} else {
		forbiddenPageContent, err := os.ReadFile(bHandler.configuration.RuleConfig.ForbiddenHTTPPath)
		//Check if an error occured when reading forbidden page
		if err != nil {
			forbiddenPageContent = []byte("Forbidden")
		}
		rawResponse := append([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"), forbiddenPageContent...)
		b64RawResponse = base64.StdEncoding.EncodeToString(rawResponse)

		//Dump the HTTP request to raw string
		rawRequest, _ := utils.DumpHTTPRequest(r)
		//Convert raw request to base64
		b64RawRequest = b64.StdEncoding.EncodeToString(rawRequest)
	}

	//Create the log structure that should be sent to the API
	logData := data.LogData{AgentId: bHandler.configuration.UUID, RemoteIP: r.RemoteAddr, Timestamp: time.Now().Unix(), Websocket: false, Request: b64RawRequest, Response: b64RawResponse, Findings: allFindings, RuleFindings: allRuleFindings}

	if true {
		bHandler.logger.Debug("Log data", logData)
	}

	if bHandler.apiWsConn != nil {
		//Send log information to the API
		apiHandler := api.NewAPIHandler(bHandler.logger, bHandler.configuration)
		_, err = apiHandler.SendLog(bHandler.apiBaseURL, logData)
		//Check if an error occured when sending log to the API
		if err != nil {
			bHandler.logger.Error(err.Error())
			//return
		}
	}

	//Send the forbidden page if the request should be dropped and the operation mode is waf
	if (requestDropped || responseDropped) && bHandler.configuration.OperationMode == "waf" {
		//Send the forbidden page
		//Read the forbidden page from the disk
		forbiddenPageContent, err := os.ReadFile(bHandler.configuration.RuleConfig.ForbiddenHTTPPath)

		//Check if an error occured when reading forbidden page
		if err != nil {
			bHandler.logger.Error("Failed to read forbidden page from disk,", err.Error())
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte("Forbidden"))
			return
		}

		//Send the content of forbidden file to client
		rw.WriteHeader(http.StatusForbidden)
		rw.Write(forbiddenPageContent)
		return
	}

	//If the mode is testing then send the log data as response
	if strings.EqualFold(bHandler.configuration.OperationMode, "testing") {
		rw.WriteHeader(http.StatusOK)
		logData.ToJSON(rw)
		return
	}

	//Send the response from the web server back to the client
	bHandler.forwardResponse(rw, response)
}
