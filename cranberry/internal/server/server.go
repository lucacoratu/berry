package server

import (
	"context"
	"cranberry/internal/config"
	"cranberry/internal/database"
	"cranberry/internal/handlers"
	"cranberry/internal/logging"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

type CranberryServer struct {
	srv           *http.Server
	logger        logging.ILogger
	configuration config.Configuration
	configFile    string
	sqlDb         *database.MysqlConnection
	osConn        *database.OpensearchConnection
}

func (server *CranberryServer) Init() error {
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

	//Initialize the database connection
	server.sqlDb = database.NewMysqlConnection(server.logger, server.configuration)
	err = server.sqlDb.Init()
	if err != nil {
		server.logger.Error("Failed to initialize sql database connection", err.Error())
		return err
	}

	server.logger.Info("Successfully connected to SQL database")

	//Initialize the opensearch connection
	server.osConn = database.NewOpensearchConnection(server.logger, server.configuration)
	err = server.osConn.Init()
	if err != nil {
		server.logger.Error("Failed to initialize OpenSearch connection", err.Error())
		return err
	}

	server.logger.Info("Successfully connected to OpenSearch database")

	//Create the router
	r := mux.NewRouter()
	//Use the logging middleware
	r.Use(server.LoggingMiddleware)

	//Create the handlers
	healthcheckHandler := handlers.NewHealthcheckHandler(server.logger, server.configuration)
	agentsHandler := handlers.NewAgentsHandler(server.logger, server.configuration, server.sqlDb, server.osConn)
	logsHandler := handlers.NewLogsHandler(server.logger, server.configuration, server.sqlDb, server.osConn)
	streamsHandler := handlers.NewStreamsHandler(server.logger, server.configuration, server.sqlDb, server.osConn)

	//Create the healthcheck route
	r.HandleFunc("/api/v1/healthcheck", healthcheckHandler.Healthcheck)

	//Create the agent register route
	r.HandleFunc("/api/v1/agents/register", agentsHandler.RegisterAgent)

	apiPostSubrouter := r.PathPrefix("/api/v1/").Methods("POST").Subrouter()
	apiGetSubrouter := r.PathPrefix("/api/v1/").Methods("GET").Subrouter()

	//Create the route that will retrieve all agents
	apiGetSubrouter.HandleFunc("/agents", agentsHandler.ViewAgents)

	//Create the route that will retrieve logs from all agents
	apiGetSubrouter.HandleFunc("/logs/http", logsHandler.ViewAllHTTPLogs)
	apiGetSubrouter.HandleFunc("/logs/tcp", logsHandler.ViewAllTCPLogs)

	//Create the route that will retrieve the methods count for HTTP logs
	apiGetSubrouter.HandleFunc("/logs/methods-stats", logsHandler.ViewMethodsCount)

	//Create the route that will retrieve a log by id
	apiGetSubrouter.HandleFunc("/logs/{id}", logsHandler.ViewLog)

	//Create the route to get all the logs from a stream based on stream UUID
	apiGetSubrouter.HandleFunc("/streams/{uuid:[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+}/logs", streamsHandler.GetStreamLogs)

	//Create the route that will receive logs from an agent
	apiPostSubrouter.HandleFunc("/agents/{uuid:[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+}/logs", logsHandler.InsertAgentLog)
	apiGetSubrouter.HandleFunc("/agents/{uuid:[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+}/logs", logsHandler.ViewAgentLogs)

	server.srv = &http.Server{
		Addr: server.configuration.ListeningAddress + ":" + server.configuration.ListeningPort,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	return nil
}

func (server *CranberryServer) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.logger.Info(r.Method, "-", r.URL.Path, r.RemoteAddr)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		// compare the return-value to the authMW
		next.ServeHTTP(w, r)
	})
}

func (server *CranberryServer) Run() {
	var wait time.Duration = 5
	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := server.srv.ListenAndServe(); err != nil {
			server.logger.Error(err.Error())
		}
	}()

	server.logger.Info("Started server on port", server.configuration.ListeningPort)

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
	server.srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	server.logger.Info("Received signal, shutting down")
	os.Exit(0)
}
