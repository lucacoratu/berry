package handlers

import (
	"cranberry/internal/config"
	"cranberry/internal/database"
	"cranberry/internal/logging"
	"cranberry/internal/models"
	"net/http"

	"github.com/google/uuid"
)

// Structure that holds data used by the agents handler
type AgentsHandler struct {
	logger        logging.ILogger
	configuration config.Configuration
	sqlDb         *database.MysqlConnection
	osConn        *database.OpensearchConnection
}

func NewAgentsHandler(logger logging.ILogger, configuration config.Configuration, sqlDb *database.MysqlConnection, osConn *database.OpensearchConnection) *AgentsHandler {
	return &AgentsHandler{logger: logger, configuration: configuration, sqlDb: sqlDb, osConn: osConn}
}

// Handler to register a new agent
func (bah *AgentsHandler) RegisterAgent(rw http.ResponseWriter, r *http.Request) {
	//Generate a new UUID
	id := uuid.New().String()
	if id == "" {
		bah.logger.Error("Failed to create new uuid for agent")
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to generate UUID"}
		cApiErr.ToJSON(rw)
		return
	}
	//Save the new agent inside the sql database
	err := bah.sqlDb.InsertAgent(id)
	if err != nil {
		bah.logger.Error("Failed to insert agent in the sql database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to insert agent"}
		cApiErr.ToJSON(rw)
		return
	}

	bah.logger.Debug("Inserted new agent with uuid", id)

	//Return the UUID to the client
	resp := models.RegisterAgentResponse{Uuid: id}
	rw.WriteHeader(http.StatusOK)
	resp.ToJSON(rw)
}

func (bah *AgentsHandler) ViewAgents(rw http.ResponseWriter, r *http.Request) {
	//Get the agents from the mysql database
	agents, err := bah.sqlDb.GetAgents()
	if err != nil {
		bah.logger.Error("Failed to get agents from sql database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to get agents"}
		cApiErr.ToJSON(rw)
		return
	}

	//Convert the database model to the view model
	var viewAgents models.ViewAgentsResponse
	for _, agent := range agents {
		//Get the number of logs collected
		logsCount, err := bah.osConn.GetAgentLogsCount(agent.UUID.String)
		//Check for errors
		//If an error occured then the logsCount will be 0 so return is not needed
		if err != nil {
			bah.logger.Error("Failed to get logs count for agent", agent.UUID.String, err.Error())
		}

		viewAgents = append(viewAgents, models.ViewAgentResponse{
			ID:            agent.ID,
			UUID:          agent.UUID.String,
			Name:          agent.Name.String,
			CreatedAt:     agent.CreatedAt,
			LogsCollected: logsCount,
		})
	}

	//Send the response to the client
	rw.WriteHeader(http.StatusOK)
	viewAgents.ToJSON(rw)
}
