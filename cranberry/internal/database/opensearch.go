package database

import (
	"context"
	"cranberry/internal/config"
	"cranberry/internal/logging"
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchapi"
)

type OpensearchConnection struct {
	logger        logging.ILogger
	configuration config.Configuration
	client        *opensearch.Client
}

func NewOpensearchConnection(logger logging.ILogger, configuration config.Configuration) *OpensearchConnection {
	return &OpensearchConnection{logger: logger, configuration: configuration}
}

// Create the index which will be used by cranberry
func (osc *OpensearchConnection) createIndex() error {
	ctx := context.Background()
	//Check if the index exists
	existsResp, err := osc.client.Indices.Exists([]string{"cranberry"})
	if err != nil {
		return err
	}

	//If the index exists it will return 200 status code
	// So the creation can be skipped
	if existsResp.StatusCode == 200 {
		osc.logger.Info("OpenSearch index exists, skipping creation")
		return nil
	}

	settings := strings.NewReader(`{
    'settings': {
        'index': {
            'number_of_shards': 1,
            'number_of_replicas': 0
            }
        }
    }`)

	createIndexReq := opensearchapi.IndicesCreateRequest{
		Index: "cranberry",
		Body:  settings,
	}

	_, err = createIndexReq.Do(ctx, osc.client.Transport)

	if err != nil {
		return err
	}

	return nil
}

func (osc *OpensearchConnection) Init() error {
	osUsername := osc.configuration.DBOptions.OpensearchOptions.Username
	osPassword := osc.configuration.DBOptions.OpensearchOptions.Password
	osAddresses := osc.configuration.DBOptions.OpensearchOptions.Addresses

	client, err := opensearch.NewClient(opensearch.Config{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Addresses: osAddresses,
		Username:  osUsername,
		Password:  osPassword,
	})

	//Check if an error occured when connecting to cluster
	if err != nil {
		return err
	}

	//Save the client inside the structure
	osc.client = client

	//Create the index
	err = osc.createIndex()
	if err != nil {
		return err
	}

	return nil
}

// func (osc *OpensearchConnection) InsertLog() error {
// 	osc.client.Index()
// 	return nil
// }
