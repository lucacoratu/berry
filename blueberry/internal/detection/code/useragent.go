package detection

import (
	"net/http"
	"strings"

	"blueberry/internal/config"
	"blueberry/internal/utils"
	"blueberry/pkg/logging"

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
	//Get the User-Agent value
	userAgent := r.Header.Get("User-Agent")
	//userAgentVal.logger.Debug(userAgent)

	//Read the blacklisted User-Agents
	blacklist, err := utils.ReadLinesFromFile(userAgentVal.configuration.BlacklistUserAgentPath)
	if err != nil {
		userAgentVal.logger.Error(userAgentVal.name, "error occured when readling user-agent blacklist:", err.Error())
		return nil, nil
	}
	//Create the slice of findings which will be returned
	findings := make([]data.FindingData, 0)

	//Check if the User-Agent header contains any blacklist element
	for _, line := range blacklist {
		if strings.Contains(userAgent, line) {
			userAgentVal.logger.Info(userAgentVal.name, "found blacklisted User-Agent:", line, "received header:", userAgent)
			//Find the line number, line index the string appears
			lineNumber, lineIndex, err := utils.FindFindingDataInRequest(r, line)
			//Check if an error occured when searching for the string in the request
			if err != nil {
				userAgentVal.logger.Error("Error occured when searching for bad user agent in request", err.Error())
				return nil, err
			}

			if lineNumber == -1 || lineIndex == -1 {
				userAgentVal.logger.Warning("The string searched couldn't be found in the request", userAgentVal.name, userAgent, line)
			}

			//Create the structure which will be returned
			returnData := data.FindingData{Line: lineNumber, LineIndex: lineIndex, Length: int64(len(line)), MatchedString: line, Classification: data.SCRIPT_USER_AGENT, Severity: data.MEDIUM, ValidatorName: userAgentVal.name}
			findings = append(findings, returnData)
			//break
		}
	}
	//Check if there is any finding
	if len(findings) == 0 {
		return nil, nil
	}

	//Something was found
	return findings, nil
}

// Validates the response (do nothing function - no User-Agent in the response)
func (userAgentVal *UserAgentValidator) ValidateResponse(r *http.Response) ([]data.FindingData, error) {
	return nil, nil
}
