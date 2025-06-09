package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"blueberry/internal/utils"

	"github.com/go-playground/validator/v10"
)

type AdaptiveTemplate struct {
	URL          string //The endpoint where the template should be used when the LLM responds
	TemplatePath string //The path to the template file
}

// Structure that will hold the configuration parameters of the proxy
type Configuration struct {
	ListeningProtocol      string             `json:"protocol" validate:"required,oneof_insensitive=http https"`                //The protocol the agent uses to communicate to users
	ListeningAddress       string             `json:"address" validate:"required,ipv4"`                                         //Address to listen on (127.0.0.1, 0.0.0.0, etc.)
	ListeningPort          string             `json:"port" validate:"required,number,gt=0,lt=65536"`                            //Port to listen on
	TLSCertificateFilepath string             `json:"tlsCertificateFilepath"`                                                   //The path to the certificate file
	TLSKeyFilepath         string             `json:"tlsKeyFilepath"`                                                           //The path to the key associated with TLS Certificate
	ForbiddenPagePath      string             `json:"forbiddenPagePath" validate:"required"`                                    //Forbidden page location
	BlacklistUserAgentPath string             `json:"blacklistUserAgentPath" validate:"required"`                               //Path to the wordlist of banned User-Agents
	ForwardServerProtocol  string             `json:"forwardServerProtocol" validate:"required"`                                //Protocol used when forwarding request to webserver
	ForwardServerAddress   string             `json:"forwardServerAddress" validate:"required"`                                 //Address of the webserver to send the request to
	ForwardServerPort      string             `json:"forwardServerPort" validate:"required,number,gt=0,lt=65536"`               //Port to forward the request to
	APIProtocol            string             `json:"apiProtocol"`                                                              //API protocol
	APIIpAddress           string             `json:"apiIpAddress"`                                                             //API ip address
	APIPort                string             `json:"apiPort"`                                                                  //API port
	UUID                   string             `json:"uuid"`                                                                     //The UUID of the agent, received after registration to the API
	RulesDirectory         string             `json:"rulesDirectory"`                                                           //The directory where rules can be found
	OperationMode          string             `json:"operationMode" validate:"required,oneof_insensitive=testing waf adaptive"` //The mode the agent will operate on (can be testing, waf, adaptive) - case insensitive
	IgnoreRulesDirectories []string           `json:"ignoreRulesDirectories"`                                                   //The directories with rules that should be ignored when loading the rules
	UseAIClassifier        bool               `json:"useAIClassifier"`                                                          //If the agent should use the AI classifier
	Classifier             string             `json:"classifier" validate:"required,oneof_insensitive=svc knn random-forest"`   //The classifier model to be used
	LLMAPIURL              string             `json:"llmAPIURL"`                                                                //The URL for the LLM API
	CreateDataset          bool               `json:"createDataset"`                                                            //If the agent should save the requests features in a dataset
	DatasetPath            string             `json:"datasetPath" validate:"required"`                                          //The path where the dataset will be saved
	AdaptiveTemplates      []AdaptiveTemplate `json:"adaptiveTemplates"`                                                        //The list of templates used when getting response from the LLM
}

// Validate function for one of (case insensitive)
// @param fl - the field level
// Returns true if the field value matches one of the specified values in the struct tag else false
func validateOneOfInsensitive(fl validator.FieldLevel) bool {
	fieldValue := fl.Field().String()
	allowedValues := strings.Split(fl.Param(), " ")

	for _, allowedValue := range allowedValues {
		if strings.EqualFold(fieldValue, allowedValue) {
			return true
		}
	}

	return false
}

// Load the configuration from a file
func (conf *Configuration) LoadConfigurationFromFile(filePath string) error {
	//Check if the file exists
	found := utils.CheckFileExists(filePath)
	if !found {
		return errors.New("configuration file cannot be found")
	}
	//Open the file and load the data into the configuration structure
	file, err := os.Open(filePath)
	//Check if an error occured when opening the file
	if err != nil {
		return err
	}
	err = conf.FromJSON(file)
	//Check if an error occured when loading the json from file
	if err != nil {
		return err
	}
	//Initialize the validator of the json data
	validate := validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("oneof_insensitive", validateOneOfInsensitive)
	//Validate the fields of the struct
	err = validate.Struct(conf)
	return err
}

// Convert from json into the configuration structure
func (conf *Configuration) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(conf)
}

// Convert to json the configuration structure
func (conf *Configuration) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(conf)
}
