package config

import (
	"io"

	"gopkg.in/yaml.v2"
)

// Structure that holds the logging options
// @fields
// LoggerType - The logger variant that should be used
// LogFilepath - The file path where the logs will be written if the file LoggerType is chosen
// Log URL - The url the log should be sent to if the remote logger is chosen
// DebugEnabled - If the debug messages should be shown by the logger
type LoggingOptions struct {
	LoggerType   string `yaml:"logger_type" mapstructure:"logger_type"`
	LogFilepath  string `yaml:"log_filepath" mapstructure:"log_filepath"`
	LogURL       string `yaml:"log_url" mapstructure:"log_url"`
	DebugEnabled bool   `yaml:"debug" mapstructure:"debug"`
}

// Structure that holds the ssl options
// @fields
// TLSCertificateFilepath - The path to the certificate file
// TLSKeyFilepath - The path to the key associated with TLS Certificate
type SSLOptions struct {
	TLSCertificateFilepath string `yaml:"certificate" mapstructure:"certificate"`
	TLSKeyFilepath         string `yaml:"key" mapstructure:"key"`
}

// Structure that holds the sql connection information
// @fields
// Username - the username used to connect to mysql server
// Password - password for user with username
// IP - the IP address to connect to
// Port - the port to connect to
// Database - the name of the database to connect to
type SQLOptions struct {
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
	IP       string `yaml:"ip" mapstructure:"ip"`
	Port     int    `yaml:"port" mapstructure:"port"`
	Database string `yaml:"database" mapstructure:"database"`
}

// Structure that holds the opensearch connection information
// @fields
// Username - username to use for login to cluster
// Password - password to use for login to cluster
// Addresses - the urls of the nodes (eg: https://127.0.0.1:9200)
type OpenSearchOptions struct {
	Username  string   `yaml:"username" mapstructure:"username"`
	Password  string   `yaml:"password" mapstructure:"password"`
	Addresses []string `yaml:"addresses" mapstructure:"addresses"`
}

// Structure that holds the database connection informations
// This application uses mysql to store details about the blueberry instances registered
// And opensearch for storing logs received from blueberry instances
// @fields
type DatabaseOptions struct {
	SqlOptions        *SQLOptions       `yaml:"sql" mapstructure:"sql"`
	OpensearchOptions OpenSearchOptions `yaml:"opensearch" mapstructure:"opensearch"`
}

// Structure which holds all the configuration fields
// @fields
// ListeningProtocol - The protocol used for listening (can be HTTP or HTTPS)
// SSLConfig - The configuration of the ssl (if needed)
// LogConfig - The logging options
type Configuration struct {
	ListeningProtocol string `yaml:"lprotocol" mapstructure:"lprotocol"`
	ListeningAddress  string `yaml:"laddress" mapstructure:"laddress"`
	ListeningPort     string `yaml:"lport" mapstructure:"lport"`

	SSLConfig *SSLOptions      `yaml:"ssl" mapstructure:"ssl"`
	LogConfig *LoggingOptions  `yaml:"logging" mapstructure:"logging"`
	DBOptions *DatabaseOptions `yaml:"db" mapstructure:"db"`
}

// Function to read the yaml config into the struct
func (conf *Configuration) FromYAML(r io.Reader) error {
	d := yaml.NewDecoder(r)
	return d.Decode(conf)
}

// Convert to yaml the config structure
func (conf *Configuration) ToYAML(w io.Writer) error {
	e := yaml.NewEncoder(w)
	return e.Encode(conf)
}
