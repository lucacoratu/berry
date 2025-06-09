package config

import (
	"io"

	"gopkg.in/yaml.v2"
)

// Structure that holds the information about the backend services the proxy should use
// @fields
// Name - The name of the service
// ListeningProtocol - The protocol the agent uses to communicate to users
// ListeningAddress - Interface address to listen on (127.0.0.1, 0.0.0.0, etc.)
// ListeningPort - Port to listen on
// RemoteURL - The URL of the remote server the requests should be sent
// RemoteProtocol - The protocol used for communication by the remote server
// RemoteAddress - The IPv4 address of the remote service
// RemotePort - The port the remote service is listening on
type BackendServices struct {
	Name string `yaml:"name" mapstructure:"name"`
	//Listen options
	ListeningProtocol string `yaml:"lprotocol" mapstructure:"lprotocol"`
	ListeningAddress  string `yaml:"laddress" mapstructure:"laddress"`
	ListeningPort     string `yaml:"lport" mapstructure:"lport"`

	//Remote service options
	RemoteURL      string `yaml:"rurl" mapstructure:"rurl"`
	RemoteProtocol string `yaml:"rprotocol" mapstructure:"rprotocol"`
	RemoteAddress  string `yaml:"raddress" mapstructure:"raddress"`
	RemotePort     string `yaml:"rport" mapstructure:"rport"`
}

// Structure that holds the rules related options
// @fields
// RulesDirectory - The directory where rules can be found
// IgnoreRulesDirectories - The directories with rules that should be ignored when loading the rules
// DefaultAction - The default actions for rules which do not specify
type RuleOptions struct {
	RulesDirectory         string   `yaml:"rules_directory" mapstructure:"rules_directory"`
	IgnoreRulesDirectories []string `yaml:"ignore_rules_directories" mapstructure:"ignore_rules_directories"`
	DefaultAction          string   `yaml:"default_action" mapstructure:"default_action"`
	ForbiddenHTTPMessage   string   `yaml:"forbidden_http_message" mapstructure:"forbidden_http_message"`
	ForbiddenHTTPPath      string   `yaml:"forbidden_http_path" mapstructure:"forbidden_http_path"`
	ForbiddenTCPMessage    string   `yaml:"forbidden_tcp_message" mapstructure:"forbidden_tcp_message"`
}

// Structure that holds the ssl options
// @fields
// TLSCertificateFilepath - The path to the certificate file
// TLSKeyFilepath - The path to the key associated with TLS Certificate
type SSLOptions struct {
	TLSCertificateFilepath string `yaml:"certificate" mapstructure:"certificate"`
	TLSKeyFilepath         string `yaml:"key" mapstructure:"key"`
}

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

// Structure that will hold the configuration parameters of the proxy
// @fields
// Services - The services the proxy will interact with
// SSLConfig - The configuration of the ssl (if needed)
// RuleConfig - The rules options
// LogConfig - The logging options
// CranberryURL - The URL of the cranberry instance
// UUID - The UUID of the instance, received after registration to the API
// OperationMode - The mode the server will operate on (can be testing, waf) - case insensitive
type Configuration struct {
	Services      []*BackendServices `yaml:"services" mapstructure:"services"`
	SSLConfig     *SSLOptions        `yaml:"ssl" mapstructure:"ssl"`
	RuleConfig    *RuleOptions       `yaml:"rules" mapstructure:"rules"`
	LogConfig     *LoggingOptions    `yaml:"logging" mapstructure:"logging"`
	CranberryURL  string             `yaml:"cranberry_url" mapstructure:"cranberry_url"`
	UUID          string             `yaml:"uuid" mapstructure:"uuid"`
	OperationMode string             `yaml:"operation_mode" mapstructure:"operation_mode"`
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
