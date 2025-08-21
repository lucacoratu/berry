package handlers

import (
	"cranberry/internal/config"
	"cranberry/internal/logging"
	"net/http"
)

// Structure that holds data used by the HealthCheck routes
type HealthcheckHandler struct {
	logger        logging.ILogger
	configuration config.Configuration
}

func NewHealthcheckHandler(logger logging.ILogger, configuration config.Configuration) *HealthcheckHandler {
	return &HealthcheckHandler{logger: logger, configuration: configuration}
}

func (hch HealthcheckHandler) Healthcheck(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)
	response := "{\"status\":\"alive\"}"
	rw.Write([]byte(response))
}
