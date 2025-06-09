package detection

import (
	"net/http"

	data "blueberry/internal/models"
)

// Interface that holds all the functions that the validators should implement
type IValidator interface {
	ValidateRequest(r *http.Request) ([]data.FindingData, error)
	ValidateResponse(r *http.Response) ([]data.FindingData, error)
}
