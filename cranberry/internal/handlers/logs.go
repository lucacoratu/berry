package handlers

import (
	"cranberry/internal/config"
	"cranberry/internal/database"
	"cranberry/internal/logging"
	"cranberry/internal/models"
	"net/http"
	"strings"

	b64 "encoding/base64"

	"github.com/gorilla/mux"
)

// Structure that holds data used by the agents handler
type LogsHandler struct {
	logger        logging.ILogger
	configuration config.Configuration
	sqlDb         *database.MysqlConnection
	osConn        *database.OpensearchConnection
}

func NewLogsHandler(logger logging.ILogger, configuration config.Configuration, sqlDb *database.MysqlConnection, osConn *database.OpensearchConnection) *LogsHandler {
	return &LogsHandler{logger: logger, configuration: configuration, sqlDb: sqlDb, osConn: osConn}
}

func (lh *LogsHandler) processHTTPLog(log models.LogData) models.ExtendedLogData {
	extendedLog := models.ExtendedLogData{LogData: log}
	//Extract the HTTP Method, URL and version from the first line of the request
	firstLine := strings.Split(log.Request, "\r\n")[0]
	aux := strings.Split(firstLine, " ")
	method, url, version := aux[0], aux[1], aux[2]

	extendedLog.HTTPMethod = method
	extendedLog.HTTPRequestURL = url
	extendedLog.HTTPRequestVersion = version

	//Extract the response version and code from the first line of the response
	firstLine = strings.Split(log.Response, "\r\n")[0]
	aux = strings.Split(firstLine, " ")
	version, code := aux[0], strings.Join(aux[1:], " ")

	extendedLog.HTTPResponseVersion = version
	extendedLog.HTTPResponseCode = code

	return extendedLog
}

func (lh *LogsHandler) processAgentLog(log models.LogData) models.ExtendedLogData {
	switch log.Type {
	case "http":
		return lh.processHTTPLog(log)
	case "websocket":
		break
	case "tcp":
		break
	case "udp":
		break
	}

	return models.ExtendedLogData{LogData: log}
}

func (lh *LogsHandler) InsertAgentLog(rw http.ResponseWriter, r *http.Request) {
	//Parse the JSON body
	logData := models.LogData{}
	err := logData.FromJSON(r.Body)
	//Check if an error occured
	if err != nil {
		lh.logger.Error("Failed to parse log data from body of request", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to parse body from JSON"}
		cApiErr.ToJSON(rw)
		return
	}

	//Convert request and response from base64
	var rawReq []byte
	if logData.Request != "" {
		rawReq, err = b64.StdEncoding.DecodeString(logData.Request)
		if err != nil {
			lh.logger.Error("Failed to decode request from base64", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			cApiErr := models.CranberryAPIError{Detail: "Failed to decode request from base64"}
			cApiErr.ToJSON(rw)
		}
	}
	var rawResp []byte
	if logData.Response != "" {
		rawResp, err = b64.StdEncoding.DecodeString(logData.Response)
		if err != nil {
			lh.logger.Error("Failed to decode request from base64", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			cApiErr := models.CranberryAPIError{Detail: "Failed to decode request from base64"}
			cApiErr.ToJSON(rw)
		}
	}

	logData.Request = string(rawReq)
	logData.Response = string(rawResp)

	//Process request and response to extract specific fields
	extendedLog := lh.processAgentLog(logData)

	//Insert the log in the opensearch database
	err = lh.osConn.InsertAgentLog(extendedLog)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to insert log"}
		cApiErr.ToJSON(rw)
	}

	lh.logger.Info("Inserted log in opensearch database")

	rw.WriteHeader(http.StatusOK)
}

// View all the logs with type == http
func (lh *LogsHandler) ViewAllHTTPLogs(rw http.ResponseWriter, r *http.Request) {
	logs, err := lh.osConn.GetLogs("http")
	if err != nil {
		lh.logger.Error("Failed to get HTTP logs from OpenSearch database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to get logs"}
		cApiErr.ToJSON(rw)
	}

	rw.WriteHeader(http.StatusOK)
	logs.ToJSON(rw)
}

// View all the logs with type == tcp
func (lh *LogsHandler) ViewAllTCPLogs(rw http.ResponseWriter, r *http.Request) {
	logs, err := lh.osConn.GetLogs("tcp")
	if err != nil {
		lh.logger.Error("Failed to get TCP logs from OpenSearch database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to get logs"}
		cApiErr.ToJSON(rw)
	}

	rw.WriteHeader(http.StatusOK)
	logs.ToJSON(rw)
}

func (lh *LogsHandler) ViewLog(rw http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	logId := vars["id"]

	log, err := lh.osConn.GetLog(logId)
	if err != nil {
		lh.logger.Error("Failed to get log from OpenSearch database", err.Error())
		rw.WriteHeader(http.StatusInternalServerError)
		cApiErr := models.CranberryAPIError{Detail: "Failed to get log"}
		cApiErr.ToJSON(rw)
		return
	}

	rw.WriteHeader(http.StatusOK)
	log.ToJSON(rw)
}

func (lh *LogsHandler) ViewAgentLogs(rw http.ResponseWriter, r *http.Request) {
	//Get the agent uuid from the URL
	vars := mux.Vars(r)
	uuid := vars["uuid"]
	//Check if the uuid is available
	if uuid == "" {
		//Send an error message
		rw.WriteHeader(http.StatusBadRequest)
		apiErr := models.CranberryAPIError{Detail: "uuid missing"}
		apiErr.ToJSON(rw)
		return
	}

	lh.osConn.GetAgentLogs(uuid)

	rw.WriteHeader(http.StatusOK)
}

// Statistics
func (lh *LogsHandler) ViewMethodsCount(rw http.ResponseWriter, r *http.Request) {
	stats, err := lh.osConn.GetMethodsCount()
	if err != nil {
		//Send an error message
		rw.WriteHeader(http.StatusBadRequest)
		apiErr := models.CranberryAPIError{Detail: "Failed to get statistics for HTTP methods"}
		apiErr.ToJSON(rw)
		return
	}

	//Send the statistics to the user
	rw.WriteHeader(http.StatusOK)
	stats.ToJSON(rw)
}
