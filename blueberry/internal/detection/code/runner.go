package detection

import (
	"net/http"

	"blueberry/internal/logging"
	data "blueberry/internal/models"
)

type ValidatorRunner struct {
	logger     logging.ILogger
	validators []IValidator
}

func NewValidatorRunner(validators []IValidator, logger logging.ILogger) *ValidatorRunner {
	return &ValidatorRunner{validators: validators, logger: logger}
}

func (vr *ValidatorRunner) RunValidatorsOnRequest(r *http.Request) ([]data.FindingData, error) {
	//Create the list of findings
	requestFindings := make([]data.FindingData, 0)

	//Run all the validators to check if the request seems valid
	for _, valid := range vr.validators {
		//Call the validate method of the validator for the request
		findingsRequest, err := valid.ValidateRequest(r)
		//Check if there was an error when looking for malicious input in the request
		if err != nil {
			vr.logger.Error("Error occured when trying to find malicious input in the request", err.Error())
		}
		//Check if there was a finding returned by the validator
		if findingsRequest != nil {
			//Add the findings to the list of findings for the request
			requestFindings = append(requestFindings, findingsRequest...)
			//Log the findings
			for _, finding := range findingsRequest {
				vr.logger.Debug(finding)
			}
		}
	}

	return requestFindings, nil
}

func (vr *ValidatorRunner) RunValidatorsOnResponse(r *http.Response) ([]data.FindingData, error) {
	//Create the structure which will hold response findings
	responseFindings := make([]data.FindingData, 0)

	//Run all the validators to check if the response seems valid
	for _, valid := range vr.validators {
		//Call the validate method of the validator for the response
		findingsResponse, err := valid.ValidateResponse(r)
		//Check if an error occured when looking for malicious input in the response
		if err != nil {
			vr.logger.Error("Error occured when trying to find malicious input in the response", err.Error())
		}
		//Check if there was any finding
		if findingsResponse != nil {
			//Add the finding to the list of response findings
			responseFindings = append(responseFindings, findingsResponse...)
			//Log the findings
			for _, finding := range findingsResponse {
				vr.logger.Debug(finding)
			}
		}
	}

	return responseFindings, nil
}
