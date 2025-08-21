package cranberry

import (
	"blueberry/internal/config"
	"blueberry/internal/logging"
	"blueberry/internal/models"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Holds data necessary in order to communicate with collector
type CranberryClient struct {
	logger        logging.ILogger
	configuration config.Configuration
}

// Creates a new instance of the APIHandler struct
func NewCranberryClient(logger logging.ILogger, configuration config.Configuration) *CranberryClient {
	return &CranberryClient{logger: logger, configuration: configuration}
}

// Registers the agent to cranberry
// This means accessing an endpoint and getting a uuid
func (cc *CranberryClient) RegisterAgent() (string, error) {
	//Get the cranberry url from the configuration
	cranberryURL := cc.configuration.CranberryURL

	//Send the data to the api
	//TODO...Add custom user agent for validation on the server
	resp, err := http.Post(cranberryURL+"/agents/register", "application/json", http.NoBody)

	//Check if an error occured when sending the request to the collector
	if err != nil {
		return "", errors.New("could not register the agent to cranberry, " + err.Error())
	}
	//Check if the response says the operation was successful and get the uuid from the body
	responseData := models.RegisterProxyResponse{}
	err = responseData.FromJSON(resp.Body)
	if err != nil {
		return "", errors.New("could not parse register response, " + err.Error())
	}

	//Return the uuid of the agent sent by the server
	return responseData.Uuid, nil
}

// Sends logs to the API
func (cc *CranberryClient) SendLog(logData models.LogData) (bool, error) {
	cc.logger.Info("Sending log to the API")
	//Parse the data into a JSON
	bodyData, err := json.Marshal(logData)
	//Check if an error occured when transforming machine info into JSON
	if err != nil {
		return false, errors.New("could not transform the log data into JSON")
	}

	//Send the data to the api
	url := fmt.Sprintf("%s/%s/%s/%s", cc.configuration.CranberryURL, "agents", cc.configuration.UUID, "logs")
	//TODO...Add custom user agent for validation on the server
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(bodyData))
	//Check if an error occured when sending the request to the collector
	if err != nil {
		return false, errors.New("could not send the logs to api, " + err.Error())
	}
	//Check the status code of the response
	if resp.StatusCode != 200 {
		apiErr := models.CranberryAPIError{}
		//Parse the error response from the API
		err := apiErr.FromJSON(resp.Body)
		//Check if an error occured when parsing the api error response
		if err != nil {
			return false, errors.New("could not parse error message from API, " + err.Error())
		}
		//Log the error message
		return false, errors.New("error on the server, detail:" + apiErr.Detail)
	}
	//The log has been added in the database
	return true, nil
}
