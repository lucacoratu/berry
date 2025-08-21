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
}

func NewAgentsHandler(logger logging.ILogger, configuration config.Configuration, sqlDb *database.MysqlConnection) *AgentsHandler {
	return &AgentsHandler{logger: logger, configuration: configuration, sqlDb: sqlDb}
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
