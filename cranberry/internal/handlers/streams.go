package handlers

import (
	"cranberry/internal/config"
	"cranberry/internal/database"
	"cranberry/internal/logging"
	"cranberry/internal/models"
	"net/http"

	"github.com/gorilla/mux"
)

// Structure that holds data used by the streams handler
type StreamsHandler struct {
	logger        logging.ILogger
	configuration config.Configuration
	sqlDb         *database.MysqlConnection
	osConn        *database.OpensearchConnection
}

func NewStreamsHandler(logger logging.ILogger, configuration config.Configuration, sqlDb *database.MysqlConnection, osConn *database.OpensearchConnection) *StreamsHandler {
	return &StreamsHandler{logger: logger, configuration: configuration, sqlDb: sqlDb, osConn: osConn}
}

// Get all the stream logs from opensearch based on the stream UUID
func (sh *StreamsHandler) GetStreamLogs(rw http.ResponseWriter, r *http.Request) {
	//Get the uuid from mux vars
	vars := mux.Vars(r)
	uuid := vars["uuid"]

	streamLogs, err := sh.osConn.GetStreamLogs(uuid)
	if err != nil {
		sh.logger.Error("Failed to get stream logs from OpenSearch database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to get stream logs"}
		cApiErr.ToJSON(rw)
	}

	rw.WriteHeader(http.StatusOK)
	streamLogs.ToJSON(rw)
}
