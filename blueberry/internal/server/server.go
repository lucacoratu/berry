package server

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"blueberry/internal/config"
	api "blueberry/internal/cranberry"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	data "blueberry/internal/models"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
	"blueberry/pkg/logging"

	"github.com/gorilla/mux"
)

type AgentServer struct {
	srv           *http.Server
	logger        logging.ILogger
	apiBaseURL    string
	configuration config.Configuration
	checkers      []code.IValidator
	rules         []rules.Rule
	configFile    string
}

// Initialize the proxy http server based on the configuration file
func (agent *AgentServer) Init() error {
	//Initialize the logger
	agent.logger = logging.NewDefaultDebugLogger()
	agent.logger.Info("Logger initialized")

	//Define command line arguments of the agent
	flag.StringVar(&agent.configFile, "config", "", "The path to the configuration file")
	//Parse command line arguments
	flag.Parse()

	//Load the configuration from file
	err := agent.configuration.LoadConfigurationFromFile(agent.configFile)
	if err != nil {
		agent.logger.Fatal("Error occured when loading the config from file,", err.Error())
		return err
	}
	agent.logger.Info("Loaded configuration from file")

	//Check if the rules directory was specified in the configuration file
	if agent.configuration.RulesDirectory != "" {
		//Load the rules from the rules directory
		allRules, err := rules.LoadRulesFromDirectory(agent.configuration, agent.logger)
		if err != nil {
			agent.logger.Error("Could not load rules from", agent.configuration.RulesDirectory, err.Error())
		}
		agent.logger.Info("Loaded", len(allRules), "rules from", agent.configuration.RulesDirectory)
		//Add the list of rules to the server structure
		agent.rules = allRules
	} else {
		agent.logger.Warning("No rules were loaded because the rules directory was not specified")
		//Assign empty slice to the rules slice of the server structure
		agent.rules = make([]rules.Rule, 0)
	}

	//Check if the listening protocol is https and if it is check if the certificate file and the key file exist on disk
	if strings.ToLower(agent.configuration.ListeningProtocol) == "https" {
		//Check if the certificate exists
		if !utils.CheckFileExists(agent.configuration.TLSCertificateFilepath) {
			agent.logger.Fatal("TLS Certificate file does not exist")
			return errors.New("Invalid TLS certificate file path")
		}

		//Check if the key exists
		if !utils.CheckFileExists(agent.configuration.TLSCertificateFilepath) {
			agent.logger.Fatal("TLS key file does not exist")
			return errors.New("Invalid TLS key file path")
		}
	}

	//Assemble the collector base URL
	agent.apiBaseURL = agent.configuration.APIProtocol + "://" + agent.configuration.APIIpAddress + ":" + agent.configuration.APIPort + "/api/v1"

	//Check connection to the api
	if !utils.CheckAPIConnection(agent.apiBaseURL) {
		agent.logger.Warning("Cannot connect to the API")
		//return errors.New("could not connect to the API")
	}

	var apiWsConnection *websocket.APIWebSocketConnection = nil
	if utils.CheckAPIConnection(agent.apiBaseURL) {
		apiHandler := api.NewAPIHandler(agent.logger, agent.configuration)

		//Check if the UUID was set inside the configuration
		if agent.configuration.UUID == "" {
			//Collect information of the operating system
			machineInfo, err := utils.GetMachineInfo()
			if err != nil {
				agent.logger.Error(err.Error())
				return err
			}

			//Log the machine info extracted
			agent.logger.Debug(machineInfo)

			//Populate information about this agent
			agentInfo := data.AgentInformation{Protocol: agent.configuration.ListeningProtocol, IPAddress: agent.configuration.ListeningAddress, Port: agent.configuration.ListeningPort, WebServerProtocol: agent.configuration.ForwardServerProtocol, WebServerIP: agent.configuration.ForwardServerAddress, WebServerPort: agent.configuration.ForwardServerPort, MachineInfo: machineInfo}

			//Send the information to the collector
			uuid, err := apiHandler.RegisterAgent(agent.apiBaseURL, agentInfo)
			if err != nil {
				agent.logger.Error("Could not register this proxy on the collector", err.Error())
				return err
			}

			agent.logger.Debug("UUID received", uuid)
			//Save the UUID into the configuration structure and write the config JSON to disk
			agent.configuration.UUID = uuid
			file, err := os.OpenFile(agent.configFile, os.O_WRONLY|os.O_TRUNC, 0644)
			//Check if an error occured when trying to open the configuration file to update it
			if err != nil {
				agent.logger.Error("Could not save the configuration file to disk, failed to open configuration file for writing, UUID not saved", err.Error())
			} else {
				newConfigContent, err := json.MarshalIndent(agent.configuration, "", "    ")
				//Check if an error occured when marshaling the json for configuration
				if err != nil {
					agent.logger.Error("Could not save the configuration file to disk, UUID not saved", err.Error())
				} else {
					//Write the new configuration to file
					_, err := file.Write(newConfigContent)
					//Check if an error occured when writing the new configuration
					if err != nil {
						agent.logger.Error("Could not write the new configuration file, UUID not saved", err.Error())
					} else {
						agent.logger.Info("Updated the configuration file to cantain the received UUID from the API")
					}
				}
			}
		}

		//Connect to the API websocket
		apiWsURL := "ws://" + agent.configuration.APIIpAddress + ":" + agent.configuration.APIPort + "/api/v1/agents/" + agent.configuration.UUID + "/ws"
		apiWsConnection = websocket.NewAPIWebSocketConnection(agent.logger, apiWsURL, agent.configuration)
		_, err = apiWsConnection.Connect()
		//Check if an error occured when connection to the API ws endpoint for the agent
		if err != nil {
			agent.logger.Error("Cannot connect to the API ws endpoint")
			return errors.New("could not connect to the API ws endpoint")
		}

		//Start waiting for messages from the server
		go apiWsConnection.Start()
	}

	//Send a test notification
	//apiWsConnection.SendNotification("Connected to the WS endpoint")

	//Add the validators to the list of validators
	agent.checkers = append(agent.checkers, code.NewUserAgentValidator(agent.logger, agent.configuration))

	//Create the router
	r := mux.NewRouter()

	//Create the handler which will contain the function to handle requests
	handler := NewAgentHandler(agent.logger, agent.apiBaseURL, agent.configuration, agent.checkers, agent.rules, apiWsConnection)

	//Create a single route that will catch every request on every method
	r.PathPrefix("/").HandlerFunc(handler.HandleRequest)

	agent.srv = &http.Server{
		Addr: agent.configuration.ListeningAddress + ":" + agent.configuration.ListeningPort,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 600,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	return nil
}

// Start the proxy server
func (agent *AgentServer) Run() {
	var wait time.Duration = 5
	// Run our server in a goroutine so that it doesn't block.
	go func() {
		//Check if it should listen on TLS
		if agent.configuration.ListeningProtocol == "https" {
			if err := agent.srv.ListenAndServeTLS(agent.configuration.TLSCertificateFilepath, agent.configuration.TLSKeyFilepath); err != nil {
				agent.logger.Error(err.Error())
			}
		} else {
			if err := agent.srv.ListenAndServe(); err != nil {
				agent.logger.Error(err.Error())
			}
		}
	}()

	agent.logger.Info("Started server on port", agent.configuration.ListeningPort)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	agent.srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	agent.logger.Info("Received signal, shutting down")
	os.Exit(0)
}
