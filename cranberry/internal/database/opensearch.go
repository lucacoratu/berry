package database

import (
	"context"
	"cranberry/internal/config"
	"cranberry/internal/logging"
	"cranberry/internal/models"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

type ShardsResponse struct {
	Total      uint `json:"total"`
	Successful uint `json:"successful"`
	Skipped    uint `json:"skipped"`
	Failed     uint `json:"failed"`
}

type CountResponse struct {
	Count  uint           `json:"count"`
	Shards ShardsResponse `json:"_shards"`
}

func (cr *CountResponse) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(cr)
}

type HitsTotalResponse struct {
	Value    uint   `json:"value"`
	Relation string `json:"relation"`
}

type InternalHitsResponse[T any] struct {
	Index  string  `json:"_index"`
	Id     string  `json:"_id"`
	Score  float32 `json:"_score"`
	Source T       `json:"_source"`
}

type HitsResponse[T any] struct {
	Total    HitsTotalResponse         `json:"total"`
	MaxScore float32                   `json:"max_score"`
	Hits     []InternalHitsResponse[T] `json:"hits"`
}

type SearchResponse[T any] struct {
	Took     uint            `json:"took"`
	TimedOut bool            `json:"timed_out"`
	Shards   ShardsResponse  `json:"_shards"`
	Hits     HitsResponse[T] `json:"hits"`
}

func (sr *SearchResponse[T]) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(sr)
}

type GetResponse[T any] struct {
	Index       string `json:"_index"`
	Id          string `json:"_id"`
	Version     int32  `json:"_version"`
	SequenceNo  int32  `json:"_seq_no"`
	PrimaryTerm int32  `json:"_primary_term"`
	Found       bool   `json:"found"`
	Source      T      `json:"_source"`
}

func (gr *GetResponse[T]) FromJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(gr)
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

func (osc *OpensearchConnection) InsertAgentLog(log models.ExtendedLogData) error {
	logData, err := json.Marshal(log)
	if err != nil {
		osc.logger.Error("Failed to marshal log data to JSON", err.Error())
		return err
	}

	logDataOS := strings.NewReader(string(logData))

	req := opensearchapi.IndexRequest{
		Index: "cranberry",
		Body:  logDataOS,
	}

	_, err = req.Do(context.Background(), osc.client)
	if err != nil {
		osc.logger.Error("Failed to insert log into OpenSearch database", err.Error())
		return err
	}

	return nil
}

func (osc *OpensearchConnection) GetLogs() (models.ViewExtendedLogsData, error) {
	//Prepare the query
	content := strings.NewReader(`{
		"size": 1000,
		"query": {
			"match_all": {}
		},
		"sort": [
			{
				"timestamp": {
					"order": "desc"
				}
			}
		]
	}`)

	search := opensearchapi.SearchRequest{
		Index: []string{"cranberry"},
		Body:  content,
	}

	searchResponse, err := search.Do(context.Background(), osc.client)
	if err != nil {
		return []models.ViewExtendedLogData{}, err
	}
	defer searchResponse.Body.Close()

	logsResp := SearchResponse[models.ViewExtendedLogData]{}
	err = logsResp.FromJSON(searchResponse.Body)

	if err != nil {
		return []models.ViewExtendedLogData{}, err
	}

	logs := []models.ViewExtendedLogData{}
	for _, hit := range logsResp.Hits.Hits {
		log := models.ViewExtendedLogData{ExtendedLogData: hit.Source.ExtendedLogData}
		log.Id = hit.Id
		logs = append(logs, log)
	}

	return logs, nil
}

func (osc *OpensearchConnection) GetAgentLogs(uuid string) (models.ViewExtendedLogData, error) {
	//Prepare the query
	content := strings.NewReader(fmt.Sprintf(`{
		"size": 1000,
		"query": {
			"multi_match": {
				"query": "%s",
				"fields": ["agentId"]
			}
		}
	}`, uuid))

	search := opensearchapi.SearchRequest{
		Index: []string{"cranberry"},
		Body:  content,
	}

	searchResponse, err := search.Do(context.Background(), osc.client)
	if err != nil {
		return models.ViewExtendedLogData{}, err
	}

	osc.logger.Debug(searchResponse.String())

	return models.ViewExtendedLogData{}, nil
}

func (osc *OpensearchConnection) GetAgentLogsCount(uuid string) (uint, error) {
	//Prepare the query
	content := strings.NewReader(fmt.Sprintf(`{
		"query": {
			"multi_match": {
				"query": "%s",
				"fields": ["agentId"]
			}
		}
	}`, uuid))

	countReq := opensearchapi.CountRequest{
		Index: []string{"cranberry"},
		Body:  content,
	}

	res, err := countReq.Do(context.Background(), osc.client)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	countResp := CountResponse{}
	err = countResp.FromJSON(res.Body)
	if err != nil {
		return 0, err
	}

	return countResp.Count, nil
}

func (osc *OpensearchConnection) GetLog(id string) (models.ViewExtendedLogData, error) {
	search := opensearchapi.GetRequest{
		Index:      "cranberry",
		DocumentID: id,
	}

	getResponse, err := search.Do(context.Background(), osc.client)
	if err != nil {
		return models.ViewExtendedLogData{}, err
	}
	defer getResponse.Body.Close()

	logResp := GetResponse[models.ViewExtendedLogData]{}
	err = logResp.FromJSON(getResponse.Body)

	if err != nil {
		return models.ViewExtendedLogData{}, err
	}

	return logResp.Source, nil
}

// HTTP Method Statistics
func (osc *OpensearchConnection) GetMethodsCount() (models.HTTPMethodStatistics, error) {
	query := `{
		"size": 0,
		"aggs": {
			"methods": {
				"terms": {
					"field": "httpMethod.keyword"
				}
			}
		}
	}`

	// Execute the search
	req := opensearchapi.SearchRequest{
		Index: []string{"cranberry"}, // replace with your index
		Body:  strings.NewReader(query),
	}

	res, err := req.Do(context.Background(), osc.client)
	if err != nil {
		return models.HTTPMethodStatistics{}, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return models.HTTPMethodStatistics{}, err
	}

	// Parse the response
	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return models.HTTPMethodStatistics{}, err
	}

	stats := models.HTTPMethodStatistics{}

	// Extract aggregation buckets
	buckets := r["aggregations"].(map[string]interface{})["methods"].(map[string]interface{})["buckets"].([]interface{})
	for _, b := range buckets {
		bucket := b.(map[string]interface{})

		switch bucket["key"] {
		case "GET":
			stats.GET = int64(bucket["doc_count"].(float64))
		case "HEAD":
			stats.HEAD = int64(bucket["doc_count"].(float64))
		case "OPTIONS":
			stats.OPTIONS = int64(bucket["doc_count"].(float64))
		case "TRACE":
			stats.TRACE = int64(bucket["doc_count"].(float64))
		case "PUT":
			stats.PUT = int64(bucket["doc_count"].(float64))
		case "DELETE":
			stats.DELETE = int64(bucket["doc_count"].(float64))
		case "POST":
			stats.POST = int64(bucket["doc_count"].(float64))
		case "PATCH":
			stats.PATCH = int64(bucket["doc_count"].(float64))
		case "CONNECT":
			stats.CONNECT = int64(bucket["doc_count"].(float64))
		}
	}

	return stats, nil
}
