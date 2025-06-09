package server

import (
	"bytes"
	"encoding/base64"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
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
type AgentHandler struct {
	logger        logging.ILogger                   //The logger interface
	apiBaseURL    string                            //The API base URL
	configuration config.Configuration              //The configuration structure
	checkers      []code.IValidator                 //The list of validators which will be run on the request and the response to find malicious activity
	rules         []rules.Rule                      //The list of rules which will try to find anomalies in the requests and the responses
	apiWsConn     *websocket.APIWebSocketConnection //The WS connection to the API
}

// Creates a new AgentHandlerStructure
func NewAgentHandler(logger logging.ILogger, apiBaseURL string, configuration config.Configuration, checkers []code.IValidator, rules []rules.Rule, apiWsConn *websocket.APIWebSocketConnection) *AgentHandler {
	return &AgentHandler{logger: logger, apiBaseURL: apiBaseURL, configuration: configuration, checkers: checkers, rules: rules, apiWsConn: apiWsConn}
}

// Forwards the request to the target server
func (agentHandler *AgentHandler) forwardRequest(req *http.Request) (*http.Response, error) {
	// we need to buffer the body if we want to read it here and send it
	// in the request.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, errors.New("could not send the request to the target web server, " + err.Error())
	}

	// you can reassign the body if you need to parse it as multipart
	req.Body = io.NopCloser(bytes.NewReader(body))

	// create a new url from the raw RequestURI sent by the client
	url := fmt.Sprintf("%s://%s%s", agentHandler.configuration.ForwardServerProtocol, agentHandler.configuration.ForwardServerAddress+":"+agentHandler.configuration.ForwardServerPort, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
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

	agentHandler.logger.Debug("Forward request, response status code", resp.StatusCode)

	return resp, nil
}

// Forwards the response back to the client
func (agentHandler *AgentHandler) forwardResponse(rw http.ResponseWriter, response *http.Response) {
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
	agentHandler.logger.Debug(response.Status)
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
func (agentHandler *AgentHandler) combineFindings(requestFindings []data.FindingData, responseFindings []data.FindingData) []data.Finding {
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

func (agentHandler *AgentHandler) combineRuleFindings(requestRuleFindings []*data.RuleFindingData, responseRuleFindings []*data.RuleFindingData) []data.RuleFinding {
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
func (agentHandler *AgentHandler) convertRequestToB64(req *http.Request) (string, error) {
	//Dump the HTTP request to raw string
	rawRequest, err := utils.DumpHTTPRequest(req)
	//Check if an error occured when dumping the request as raw string
	if err != nil {
		agentHandler.logger.Error(err.Error())
		return "", err
	}
	//Convert raw request to base64
	b64RawRequest := b64.StdEncoding.EncodeToString(rawRequest)
	//Return the base64 string of the request and the response
	return b64RawRequest, nil
}

// Converts the request and the response to raw string then base64 encodes both of them
func (agentHandler *AgentHandler) convertRequestAndResponseToB64(req *http.Request, resp *http.Response) (string, string, error) {
	//Dump the HTTP request to raw string
	rawRequest, _ := utils.DumpHTTPRequest(req)
	//Dump the response as raw string
	rawResponse, err := utils.DumpHTTPResponse(resp)
	//Check if an error occured when dumping the response as raw string
	if err != nil {
		agentHandler.logger.Error(err.Error())
		return "", "", err
	}
	//Convert raw request to base64
	b64RawRequest := b64.StdEncoding.EncodeToString(rawRequest)
	//Convert raw response to base64
	b64RawResponse := b64.StdEncoding.EncodeToString(rawResponse)
	//Return the base64 string of the request and the response
	return b64RawRequest, b64RawResponse, nil
}

// Sends the raw request encoded base64 to the LLM API
// Returns LLMResponseData which will contain a series of headers and a body generated by the LLM
func (agentHandler *AgentHandler) sendB64RequestToLLMAPI(req *http.Request, classification string) *data.LLMResponse {
	//Convert raw HTTP request to base64
	rawRequest, _ := utils.DumpHTTPRequest(req)
	b64RawRequest := b64.StdEncoding.EncodeToString(rawRequest)

	//Create the request to the LLM API
	model := "honeypot"
	requestURL := fmt.Sprintf("%s/generic?raw_request=%s&classification=%s&model=%s", agentHandler.configuration.LLMAPIURL, b64RawRequest, classification, model)
	llm_req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		agentHandler.logger.Error("Failed to create request to LLM API", err.Error())
		return nil
	}

	//Create the http client
	client := http.Client{
		Timeout: 10 * time.Minute,
	}

	//Send the request to the LLM API
	llm_response, err := client.Do(llm_req)
	if err != nil {
		agentHandler.logger.Error("Failed to send request to LLM API", err.Error())
		return nil
	}

	//Parse the response from the LLM
	var llm_response_data data.LLMResponse
	// err = llm_response_data.FromJSON(llm_response.Body)
	// if err != nil {
	// 	agentHandler.logger.Error("Failed to decode JSON from LLM API response", err.Error())
	// 	return nil
	// }
	llm_response_data.Headers = nil
	llm_response_body_data, err := io.ReadAll(llm_response.Body)
	if err != nil {
		agentHandler.logger.Error("Failed to read LLM API response", err.Error())
		return nil
	}
	llm_response_data.Body = string(llm_response_body_data)

	return &llm_response_data
}

func (agentHandler *AgentHandler) sendAdaptiveLogToApi(r *http.Request, requestFindings []data.FindingData, requestRuleFindings []*data.RuleFindingData, llm_response_data data.LLMResponse) {
	allFindings := agentHandler.combineFindings(requestFindings, make([]data.FindingData, 0))
	//Combine the rule findings into a single structure
	allRuleFindings := agentHandler.combineRuleFindings(requestRuleFindings, make([]*data.RuleFindingData, 0))

	//Convert the request to base64 string
	b64RawRequest, _ := agentHandler.convertRequestToB64(r)

	//Create the response based on the headers and the body received from LLM API
	var rawResponse string = "HTTP/1.1 200 OK\r\n"
	//Add the headers
	for header_name, header_value := range llm_response_data.Headers {
		rawResponse += fmt.Sprintf("%s: %s\r\n", header_name, header_value)
	}
	//Add an empty line
	rawResponse += "\r\n"
	//Add the body
	rawResponse += llm_response_data.Body

	agentHandler.logger.Debug(rawResponse)

	//Convert the raw response to base64
	b64RawResponse := b64.StdEncoding.EncodeToString([]byte(rawResponse))

	//Create the log structure that should be sent to the API
	logData := data.LogData{AgentId: agentHandler.configuration.UUID, RemoteIP: r.RemoteAddr, Timestamp: time.Now().Unix(), Request: b64RawRequest, Response: b64RawResponse, Findings: allFindings, RuleFindings: allRuleFindings}

	if agentHandler.apiWsConn != nil {
		agentHandler.logger.Debug("Sending log in adaptive mode to the API...")
		//Send log information to the API
		apiHandler := api.NewAPIHandler(agentHandler.logger, agentHandler.configuration)
		_, err := apiHandler.SendLog(agentHandler.apiBaseURL, logData)
		//Check if an error occured when sending log to the API
		if err != nil {
			agentHandler.logger.Error(err.Error())
			//return
		}
	}
}

// Handle the request if the agent is running adaptive mode of operation
func (agentHandler *AgentHandler) HandleAdaptiveOperationMode(rw http.ResponseWriter, r *http.Request, requestFindings []data.FindingData, requestRuleFindings []*data.RuleFindingData, aiClassification string) {
	//Check if the request should be sent to the LLM API
	//If it shouldn't be sent then serve a static page

	//Check if the ai classifier says the request is benign and the rules didn't find anything
	agentHandler.logger.Debug(aiClassification)
	if len(requestRuleFindings) == 0 && aiClassification == "benign" {
		agentHandler.logger.Debug("The request is benign, sending the request to the target web server")
		//Send the request to the target server and send the response to the client
		response, err := agentHandler.forwardRequest(r)
		if err != nil {
			agentHandler.logger.Error("Failed to send request to target server", err.Error())
			return
		}
		//Forward the response back to the client
		agentHandler.forwardResponse(rw, response)

		allFindings := agentHandler.combineFindings(requestFindings, make([]data.FindingData, 0))
		//Combine the rule findings into a single structure
		allRuleFindings := agentHandler.combineRuleFindings(requestRuleFindings, make([]*data.RuleFindingData, 0))

		//Convert the request to base64 string
		b64RawRequest, b64RawResponse, _ := agentHandler.convertRequestAndResponseToB64(r, response)

		//Create the log structure that should be sent to the API
		logData := data.LogData{AgentId: agentHandler.configuration.UUID, RemoteIP: r.RemoteAddr, Timestamp: time.Now().Unix(), Request: b64RawRequest, Response: b64RawResponse, Findings: allFindings, RuleFindings: allRuleFindings}

		if agentHandler.apiWsConn != nil {
			agentHandler.logger.Debug("Sending log in adaptive mode to the API...")
			//Send log information to the API
			apiHandler := api.NewAPIHandler(agentHandler.logger, agentHandler.configuration)
			_, err := apiHandler.SendLog(agentHandler.apiBaseURL, logData)
			//Check if an error occured when sending log to the API
			if err != nil {
				agentHandler.logger.Error(err.Error())
				//return
			}
		}

		return
	}

	//Decide the final classification
	requestFinalClassification := aiClassification
	var occurencesClassificationsRule map[string]int = make(map[string]int, 0)
	//Compute the most detected payload classification from rules
	for _, ruleFinding := range requestRuleFindings {
		_, ok := occurencesClassificationsRule[ruleFinding.Classification]
		if !ok {
			occurencesClassificationsRule[ruleFinding.Classification] = 0
		}
		occurencesClassificationsRule[ruleFinding.Classification] += 1
	}

	var maxOccurencesClassification int = 0
	var ruleClassification string = ""
	for key, value := range occurencesClassificationsRule {
		if value > maxOccurencesClassification {
			ruleClassification = key
			maxOccurencesClassification = value
		}
	}

	if ruleClassification != aiClassification {
		requestFinalClassification = ruleClassification
	}

	//Send the request
	agentHandler.logger.Debug("Sending request to LLM API...")
	llm_response_data := agentHandler.sendB64RequestToLLMAPI(r, requestFinalClassification)

	//Check if the response from LLM is valid (not nil)
	if llm_response_data == nil {
		agentHandler.logger.Error("Received invalid response from LLM API, sending a default message to the client...")
		//Send the response back to the client
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("Ok"))
		return
	}

	//Debug log the response from the LLM API
	agentHandler.logger.Debug(*llm_response_data)

	//Add the headers to the response
	for header_name, header_value := range llm_response_data.Headers {
		rw.Header().Set(header_name, header_value)
	}

	//Send the response back to the client
	rw.WriteHeader(http.StatusOK)

	agentHandler.logger.Debug("Sending body...")

	//Check if the endpoint is defined in the templates
	//Templates will be used to mark the location in the HTML page where the response from the LLM API will be inserted
	//This will be useful when wanting to mimic a website
	//There should exist a default template
	var templateSent bool = false
	for _, adaptive_template := range agentHandler.configuration.AdaptiveTemplates {
		if r.URL.Path == adaptive_template.URL {
			//Load the template from the template path
			tmpl, err := template.ParseFiles(adaptive_template.TemplatePath)
			if err != nil {
				agentHandler.logger.Error("Failed to load template from ", adaptive_template.TemplatePath, err.Error())
				templateSent = false
			}
			//Create the structure which will be used inside html template
			templateVar := data.TemplateLLMResponse{LLM_Template_Response: llm_response_data.Body}
			agentHandler.logger.Debug("Sending template for", r.URL.Path)
			err = tmpl.Execute(rw, templateVar)
			if err != nil {
				agentHandler.logger.Error("Failed to execute template from", adaptive_template.TemplatePath, err.Error())
				templateSent = false
			}
			templateSent = true
			break
		}
	}

	//Send the body
	if !templateSent {
		agentHandler.logger.Debug("Response body", llm_response_data.Body)
		rw.Write([]byte(llm_response_data.Body))
	}

	//Send the data to the API

	//Combine the findings into a single structure
	//In this case the response findings will always be empty list
	agentHandler.sendAdaptiveLogToApi(r, requestFindings, requestRuleFindings, *llm_response_data)

}

// Handle the request if the agent is running in waf operation mode
// @param requestFindings the code findings after checking the request
// @param requestRuleFindings the findings after applying the rules on the request
// Returns bool (true if the request should be dropped, false if should be allowed)
// Returns error if an error occured during the handling of findings
func (agentHandler *AgentHandler) HandleWAFOperationModeOnRequest(requestFindings []data.FindingData, requestRuleFindings []*data.RuleFindingData) (bool, error) {
	//Loop through all the code findings

	//Loop through all the rules findings
	for _, ruleFinding := range requestRuleFindings {
		//Get the id of the rule
		ruleAction := rules.GetRuleAction(agentHandler.rules, ruleFinding.RuleId)
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
func (agentHandler *AgentHandler) HandleWAFOperationModeOnResponse(responseFindings []data.FindingData, responseRuleFindings []*data.RuleFindingData) (bool, error) {
	//Loop through all the code findings

	//Loop through all the rules findings
	for _, ruleFinding := range responseRuleFindings {
		//Get the id of the rule
		ruleAction := rules.GetRuleAction(agentHandler.rules, ruleFinding.RuleId)
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
func (agentHandler *AgentHandler) HandleWebsocketConnection(rw http.ResponseWriter, r *http.Request) {
	// Upgrade incoming HTTP request to WebSocket
	clientConn, err := upgrader.Upgrade(rw, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer clientConn.Close()

	agentHandler.logger.Debug("Upgraded to websocket connection")

	//Create the target server
	targetServer := agentHandler.configuration.ForwardServerAddress + ":" + agentHandler.configuration.ForwardServerPort
	agentHandler.logger.Debug("Forwarding websocket messages to", targetServer)

	// Dial to target backend WebSocket server
	backendURL := url.URL{Scheme: "ws", Host: targetServer, Path: r.URL.Path}
	backendConn, _, err := ws_gorilla.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		log.Println("Dial error:", err)
		return
	}
	defer backendConn.Close()

	// Proxy messages between client and backend
	errc := make(chan error, 2)

	//Proxy messages from client to the backend web server
	go agentHandler.proxyWS(clientConn, backendConn, errc)
	//Proxy messages from the backend web server to the client
	go agentHandler.proxyWS(backendConn, clientConn, errc)

	<-errc // wait for first error or disconnect
}

func (agentHandler *AgentHandler) proxyWS(src, dest *ws_gorilla.Conn, errc chan error) {
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(agentHandler.logger, agentHandler.rules, agentHandler.apiWsConn, agentHandler.configuration)

	for {
		mt, message, err := src.ReadMessage()
		if err != nil {
			agentHandler.logger.Error("Websocket connection closed,", err.Error())
			errc <- err
			return
		}

		//Apply the rules on the websocket messages
		findings, err := ruleRunner.RunRulesOnWebsocketMessage(mt, message)
		if err != nil {
			agentHandler.logger.Error("Error when running rules on websocket message", err.Error())
		}
		agentHandler.logger.Debug(findings)

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
			if agentHandler.configuration.OperationMode == "waf" {
				rule_action := rules.GetRuleAction(agentHandler.rules, finding.RuleId)
				if rule_action == "drop" || rule_action == "" {
					requestBlocked = true
				}
			}
		}

		//Initialize the forbidden message
		forbiddenMessage := []byte("{\"status_code\": 403, \"message\": \"Forbidden, you do not have permissions to access this resource\"}")

		//Create the log structure that should be sent to the API
		logData := data.LogData{AgentId: agentHandler.configuration.UUID, RemoteIP: src.NetConn().RemoteAddr().String(), Timestamp: time.Now().Unix(), Websocket: true, Request: b64RawRequest, Response: "", Findings: nil, RuleFindings: allFindings}

		//If the request is blocked then add the forbidden message as response in the log data
		if requestBlocked {
			logData.Response = b64.StdEncoding.EncodeToString(forbiddenMessage)
		}

		agentHandler.logger.Debug("Log data", logData)

		//Send the findings to the API
		if agentHandler.apiWsConn != nil {
			//Send log information to the API
			apiHandler := api.NewAPIHandler(agentHandler.logger, agentHandler.configuration)
			_, err = apiHandler.SendLog(agentHandler.apiBaseURL, logData)
			//Check if an error occured when sending log to the API
			if err != nil {
				agentHandler.logger.Error(err.Error())
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
				agentHandler.logger.Error("Websocket connection closed,", err.Error())
				errc <- err
				return
			}
		}
	}
}

// Handles the requests received by the agent
func (agentHandler *AgentHandler) HandleRequest(rw http.ResponseWriter, r *http.Request) {
	//Check if the request is a websocket upgrade
	if ws_gorilla.IsWebSocketUpgrade(r) {
		agentHandler.logger.Debug("Websocket upgrade message received")
		//Handle the websocket connection separately
		agentHandler.HandleWebsocketConnection(rw, r)
		//Return from the function
		return
	}

	//Log the endpoint where the request was made
	agentHandler.logger.Info("Received", r.Method, "request on", r.URL.Path)

	//If the requested path is favicon.ico then return the file from the static folder
	if r.URL.Path == "/favicon.ico" {
		http.ServeFile(rw, r, "./static/favicon.ico")
		return
	}

	//Create the validator runner
	validatorRunner := code.NewValidatorRunner(agentHandler.checkers, agentHandler.logger)
	//Create the rule runner
	ruleRunner := rules.NewRuleRunner(agentHandler.logger, agentHandler.rules, agentHandler.apiWsConn, agentHandler.configuration)

	//Run all the validators on the request
	requestFindings, _ := validatorRunner.RunValidatorsOnRequest(r)
	//Run all the rules on the request
	requestRuleFindings, _ := ruleRunner.RunRulesOnRequest(r)
	//Run the ai classifier on the request
	requestClassification := ""

	//Log request findings
	agentHandler.logger.Debug("Request findings", requestFindings)
	//Log the request rule findings
	agentHandler.logger.Debug("Request rule findings", requestRuleFindings)

	//If the mode of operation is waf check the action from the rule
	//If the action specified inside the rule is block then the forbidden page should be sent to the client
	var requestDropped bool = false
	var err error = nil

	if agentHandler.configuration.OperationMode == "waf" {
		requestDropped, err = agentHandler.HandleWAFOperationModeOnRequest(requestFindings, requestRuleFindings)
		if err != nil {
			agentHandler.logger.Error("Error occured when handling waf operation mode on request", err.Error())
		}
	}

	//If the mode of operation is adaptive then send the raw request encoded base64 to LLM
	if agentHandler.configuration.OperationMode == "adaptive" {
		agentHandler.HandleAdaptiveOperationMode(rw, r, requestFindings, requestRuleFindings, requestClassification)
		//The function handles everything so we can return
		return
	}

	//Check if the operation mode is waf and the forbidden page has been returned
	//If the forbidden page has been returned then the request should not be forwarded to the target service
	//Also the rules and validators shouldn't be applied on response (as it will always be the forbidden page)

	var response *http.Response = nil
	var responseFindings []data.FindingData = make([]data.FindingData, 0)
	var responseRuleFindings []*data.RuleFindingData = make([]*data.RuleFindingData, 0)

	//Initialize the response dropped
	var responseDropped bool = false

	if !requestDropped || agentHandler.configuration.OperationMode != "waf" {
		//Forward the request to the destination web server
		response, err = agentHandler.forwardRequest(r)
		if err != nil {
			agentHandler.logger.Error(err.Error())
			return
		}

		//Run the validators on the response
		responseFindings, _ = validatorRunner.RunValidatorsOnResponse(response)
		//Run the rules on the response
		responseRuleFindings, _ = ruleRunner.RunRulesOnResponse(response)

		//Log response findings
		agentHandler.logger.Debug("Response findings", responseFindings)
		//Log the rules response findings
		agentHandler.logger.Debug("Response rule findings", responseRuleFindings)

		//Check if the response should be dropped
		responseDropped, err = agentHandler.HandleWAFOperationModeOnResponse(responseFindings, responseRuleFindings)
		if err != nil {
			agentHandler.logger.Error("Error occured when handling waf operation mode on request", err.Error())
		}
	}

	//Combine the findings into a single structure
	//If the request is not forwarded then the response findings should be empty arrays
	allFindings := agentHandler.combineFindings(requestFindings, responseFindings)
	//Combine the rule findings into a single structure
	allRuleFindings := agentHandler.combineRuleFindings(requestRuleFindings, responseRuleFindings)

	//Convert the request and response to base64 string
	//If the response is nil (the request was dropped then convert the forbidden page to base64)
	var b64RawRequest string = ""
	var b64RawResponse string = ""
	if !requestDropped {
		b64RawRequest, b64RawResponse, _ = agentHandler.convertRequestAndResponseToB64(r, response)
	} else {
		forbiddenPageContent, err := os.ReadFile(agentHandler.configuration.ForbiddenPagePath)
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
	logData := data.LogData{AgentId: agentHandler.configuration.UUID, RemoteIP: r.RemoteAddr, Timestamp: time.Now().Unix(), Websocket: false, Request: b64RawRequest, Response: b64RawResponse, Findings: allFindings, RuleFindings: allRuleFindings}

	if true {
		agentHandler.logger.Debug("Log data", logData)
	}

	if agentHandler.apiWsConn != nil {
		//Send log information to the API
		apiHandler := api.NewAPIHandler(agentHandler.logger, agentHandler.configuration)
		_, err = apiHandler.SendLog(agentHandler.apiBaseURL, logData)
		//Check if an error occured when sending log to the API
		if err != nil {
			agentHandler.logger.Error(err.Error())
			//return
		}
	}

	//Send the forbidden page if the request should be dropped and the operation mode is waf
	if (requestDropped || responseDropped) && agentHandler.configuration.OperationMode == "waf" {
		//Send the forbidden page
		//Read the forbidden page from the disk
		forbiddenPageContent, err := os.ReadFile(agentHandler.configuration.ForbiddenPagePath)

		//Check if an error occured when reading forbidden page
		if err != nil {
			agentHandler.logger.Error("Failed to read forbidden page from disk,", err.Error())
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
	if strings.EqualFold(agentHandler.configuration.OperationMode, "testing") {
		rw.WriteHeader(http.StatusOK)
		logData.ToJSON(rw)
		return
	}

	//Send the response from the web server back to the client
	agentHandler.forwardResponse(rw, response)
}
