package detection

import (
	"net/http"

	"blueberry/internal/config"
	"blueberry/internal/logging"

	data "blueberry/internal/models"
)

type UserAgentValidator struct {
	configuration config.Configuration
	logger        logging.ILogger
	name          string
}

// Creates an instance of the UserAgentValidator
func NewUserAgentValidator(logger logging.ILogger, configuration config.Configuration) *UserAgentValidator {
	return &UserAgentValidator{logger: logger, name: "UserAgentValidator", configuration: configuration}
}

// Gets the name of the validator
func (userAgentVal *UserAgentValidator) GetName() string {
	return userAgentVal.name
}

// Validates the User-Agent header from the request by using a black list approach
func (userAgentVal *UserAgentValidator) ValidateRequest(r *http.Request) ([]data.FindingData, error) {
	//Something was found
	return nil, nil
}

// Validates the response (do nothing function - no User-Agent in the response)
func (userAgentVal *UserAgentValidator) ValidateResponse(r *http.Response) ([]data.FindingData, error) {
	return nil, nil
}
