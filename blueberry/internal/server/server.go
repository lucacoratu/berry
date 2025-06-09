package server

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"blueberry/internal/config"
	code "blueberry/internal/detection/code"
	rules "blueberry/internal/detection/rules"
	"blueberry/internal/server/handlers"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
	"blueberry/pkg/logging"

	"github.com/gorilla/mux"
)

// Proxy server is the abstraction used by the Blueberry server to manage the proxy instances
// @fields
// ServerType - The underling server type (can be http, https, tcp, tcps) - the same available in the configuration
// ServerAddress - The address the server is listening on
// ServerPort - The port the server is listening on
// httpServer - The http server to be used in case the ServerType is http
// TODO...TCP server type
type ProxyServer struct {
	ServerProtocol string
	ServerAddress  string
	ServerPort     string
	HttpServer     *http.Server
	//tcpServer *
}

// Structure that holds the information needed to run blueberry
type BlueberryServer struct {
	proxyServers  []*ProxyServer
	logger        logging.ILogger
	apiBaseURL    string
	configuration config.Configuration
	checkers      []code.IValidator
	rules         []rules.Rule
	configFile    string
}

// Initialize the proxy http server based on the configuration file
func (server *BlueberryServer) Init() error {
	//Initialize the logger
	server.logger = logging.NewDefaultLogger()
	server.logger.Info("Logger initialized")

	//Define command line arguments of the server
	flag.StringVar(&server.configFile, "config", "./config.yaml", "The path to the configuration file")
	//Parse command line arguments
	flag.Parse()

	//Load the configuration from file
	server.logger.Info("Loading configuration from", server.configFile)
	configuration, err := config.LoadConfigurationFromFile(server.configFile)
	if err != nil {
		server.logger.Fatal("Error occured when loading the config from file,", err.Error())
		return err
	}
	server.configuration = *configuration
	server.logger.Info("Loaded configuration from file")

	//Load the new logger based on the options in the config file
	if server.configuration.LogConfig.DebugEnabled {
		server.logger = logging.NewDefaultDebugLogger()
	}

	//Check if the rules directory was specified in the configuration file
	if server.configuration.RuleConfig.RulesDirectory != "" {
		//Load the rules from the rules directory
		allRules, err := rules.LoadRulesFromDirectory(server.configuration, server.logger)
		if err != nil {
			server.logger.Error("Could not load rules from", server.configuration.RuleConfig.RulesDirectory, err.Error())
		}
		server.logger.Info("Loaded", len(allRules), "rules from", server.configuration.RuleConfig.RulesDirectory)
		//Add the list of rules to the server structure
		server.rules = allRules
	} else {
		server.logger.Warning("No rules were loaded because the rules directory was not specified")
		//Assign empty slice to the rules slice of the server structure
		server.rules = make([]rules.Rule, 0)
	}

	//Check if the listening protocol is https and if it is check if the certificate file and the key file exist on disk
	if strings.ToLower(server.configuration.Services[0].ListeningProtocol) == "https" {
		//Check if the certificate exists
		if !utils.CheckFileExists(server.configuration.SSLConfig.TLSCertificateFilepath) {
			server.logger.Fatal("TLS Certificate file does not exist")
			return errors.New("Invalid TLS certificate file path")
		}

		//Check if the key exists
		if !utils.CheckFileExists(server.configuration.SSLConfig.TLSKeyFilepath) {
			server.logger.Fatal("TLS key file does not exist")
			return errors.New("Invalid TLS key file path")
		}
	}

	//Assemble the collector base URL
	//server.apiBaseURL = server.configuration.APIProtocol + "://" + server.configuration.APIIpAddress + ":" + server.configuration.APIPort + "/api/v1"
	server.apiBaseURL = server.configuration.CranberryURL

	//Check connection to the api
	if !utils.CheckAPIConnection(server.apiBaseURL) {
		server.logger.Warning("Cannot connect to the API")
		//return errors.New("could not connect to the API")
	}

	var apiWsConnection *websocket.APIWebSocketConnection = nil
	// if utils.CheckAPIConnection(server.apiBaseURL) {
	// 	apiHandler := api.NewAPIHandler(server.logger, server.configuration)

	// 	//Check if the UUID was set inside the configuration
	// 	if server.configuration.UUID == "" {
	// 		//Collect information of the operating system
	// 		machineInfo, err := utils.GetMachineInfo()
	// 		if err != nil {
	// 			server.logger.Error(err.Error())
	// 			return err
	// 		}

	// 		//Log the machine info extracted
	// 		server.logger.Debug(machineInfo)

	// 		//Populate information about this server
	// 		serverInfo := data.serverInformation{Protocol: server.configuration.ListeningProtocol, IPAddress: server.configuration.ListeningAddress, Port: server.configuration.ListeningPort, WebServerProtocol: server.configuration.ForwardServerProtocol, WebServerIP: server.configuration.ForwardServerAddress, WebServerPort: server.configuration.ForwardServerPort, MachineInfo: machineInfo}

	// 		//Send the information to the collector
	// 		uuid, err := apiHandler.Registerserver(server.apiBaseURL, serverInfo)
	// 		if err != nil {
	// 			server.logger.Error("Could not register this proxy on the collector", err.Error())
	// 			return err
	// 		}

	// 		server.logger.Debug("UUID received", uuid)
	// 		//Save the UUID into the configuration structure and write the config JSON to disk
	// 		server.configuration.UUID = uuid
	// 		file, err := os.OpenFile(server.configFile, os.O_WRONLY|os.O_TRUNC, 0644)
	// 		//Check if an error occured when trying to open the configuration file to update it
	// 		if err != nil {
	// 			server.logger.Error("Could not save the configuration file to disk, failed to open configuration file for writing, UUID not saved", err.Error())
	// 		} else {
	// 			newConfigContent, err := json.MarshalIndent(server.configuration, "", "    ")
	// 			//Check if an error occured when marshaling the json for configuration
	// 			if err != nil {
	// 				server.logger.Error("Could not save the configuration file to disk, UUID not saved", err.Error())
	// 			} else {
	// 				//Write the new configuration to file
	// 				_, err := file.Write(newConfigContent)
	// 				//Check if an error occured when writing the new configuration
	// 				if err != nil {
	// 					server.logger.Error("Could not write the new configuration file, UUID not saved", err.Error())
	// 				} else {
	// 					server.logger.Info("Updated the configuration file to cantain the received UUID from the API")
	// 				}
	// 			}
	// 		}
	// 	}

	// 	//Connect to the API websocket
	// 	apiWsURL := "ws://" + server.configuration.APIIpAddress + ":" + server.configuration.APIPort + "/api/v1/servers/" + server.configuration.UUID + "/ws"
	// 	apiWsConnection = websocket.NewAPIWebSocketConnection(server.logger, apiWsURL, server.configuration)
	// 	_, err = apiWsConnection.Connect()
	// 	//Check if an error occured when connection to the API ws endpoint for the server
	// 	if err != nil {
	// 		server.logger.Error("Cannot connect to the API ws endpoint")
	// 		return errors.New("could not connect to the API ws endpoint")
	// 	}

	// 	//Start waiting for messages from the server
	// 	go apiWsConnection.Start()
	// }

	//Send a test notification
	//apiWsConnection.SendNotification("Connected to the WS endpoint")

	//Add the validators to the list of validators
	//server.checkers = append(server.checkers, code.NewUserserverValidator(server.logger, server.configuration))
	//Loop through the services and create a proxy server for each of them
	for _, service := range server.configuration.Services {
		//If the service listening protocol is http create a http server
		if service.ListeningProtocol == "http" || service.ListeningProtocol == "https" {
			//Create the router
			r := mux.NewRouter()

			//Create the handler which will contain the function to handle requests
			handler := handlers.NewBlueberryHTTPHandler(server.logger, server.apiBaseURL, server.configuration, service.RemoteURL, server.checkers, server.rules, apiWsConnection)

			//Create a single route that will catch every request on every method
			r.PathPrefix("/").HandlerFunc(handler.HandleRequest)

			server.proxyServers = append(server.proxyServers,
				&ProxyServer{
					ServerProtocol: service.ListeningProtocol,
					ServerAddress:  service.ListeningAddress,
					ServerPort:     service.ListeningPort,
					HttpServer: &http.Server{
						Addr: service.ListeningAddress + ":" + service.ListeningPort,
						// Good practice to set timeouts to avoid Slowloris attacks.
						WriteTimeout: time.Second * 60,
						ReadTimeout:  time.Second * 15,
						IdleTimeout:  time.Second * 60,
						Handler:      r, // Pass our instance of gorilla/mux in.
					}})
		}
	}

	return nil
}

// Start the proxy server
func (server *BlueberryServer) Run() {
	var wait time.Duration = 5

	// Run the http servers in a goroutine so that it doesn't block.
	for _, proxyServer := range server.proxyServers {
		go func() {
			//Check if it should listen on TLS
			if proxyServer.ServerProtocol == "https" {
				if err := proxyServer.HttpServer.ListenAndServeTLS(server.configuration.SSLConfig.TLSCertificateFilepath, server.configuration.SSLConfig.TLSKeyFilepath); err != nil {
					server.logger.Error(err.Error())
				}
			} else {
				if err := proxyServer.HttpServer.ListenAndServe(); err != nil {
					if errors.Is(err, http.ErrServerClosed) {
						server.logger.Info("Received shutdown, server on port", proxyServer.ServerPort, "closed")
						return
					}
					server.logger.Error(err.Error())
				}
			}

		}()
		server.logger.Info("Started server on port", proxyServer.ServerPort)
	}

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

	//Close all the servers
	for _, proxyServer := range server.proxyServers {
		if proxyServer.ServerProtocol == "http" || proxyServer.ServerProtocol == "https" {
			proxyServer.HttpServer.Shutdown(ctx)
		}
	}

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	server.logger.Info("Received signal, shutting down")
	os.Exit(0)
}
