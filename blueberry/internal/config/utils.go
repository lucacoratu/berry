package config

import (
	"blueberry/internal/utils"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

var allowedProtocols []string = []string{"http", "tcp", "https", "tcps"}

// Adds the default values to missing fields in the configuration
func completeDefaultValues(conf *Configuration) {
	//For every service check if the remote url is set
	//If the remote url is not set then make it from remote protocol, remote address and remote port
	//If the remote url is set and remote protocol or remote address or remote port are not set, complete them based on the url
	//If the name is not set then set it to Service {port}
	for i, service := range conf.Services {
		if service.Name == "" {
			conf.Services[i].Name = fmt.Sprintf("Service %s", service.ListeningPort)
		}

		if service.RemoteURL == "" {
			conf.Services[i].RemoteURL = fmt.Sprintf("%s://%s:%s", service.RemoteProtocol, service.RemoteAddress, service.RemotePort)
		}

		if service.RemoteURL != "" {
			//Parse the remote URL
			u, _ := url.Parse(service.RemoteURL)
			conf.Services[i].RemoteProtocol = u.Scheme
			conf.Services[i].RemoteAddress = u.Hostname()
			conf.Services[i].RemotePort = u.Port()
		}
	}

	//If the default forbidden message is missing for http
	if conf.RuleConfig.ForbiddenHTTPMessage == "" {
		conf.RuleConfig.ForbiddenHTTPMessage = `
		<html>
			<h1>Forbidden</h1>
			<p>You don't have access for this resource</p>
			<p>If you think you did nothing wrong, contact the administrator</p>
		</html>
		`
	}

	//If the default forbidden message is missing for tcp
	if conf.RuleConfig.ForbiddenTCPMessage == "" {
		conf.RuleConfig.ForbiddenTCPMessage = "Forbidden\n"
	}

	//If the operation mode is not specified then it will be waf
	if conf.OperationMode == "" {
		conf.OperationMode = "waf"
	}
}

// Checks if string is valid ip address (either ipv4 or ipv6)
func isValidIPAddress(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}
	return true
}

// Check if port string is valid >= 1 && <= 65535
func isValidPort(port string) bool {
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return intPort >= 1 && intPort <= 65535
}

// Check is valid url
func isValidURL(tested_url string) bool {
	u, err := url.Parse(tested_url)
	//Check for parsing errors
	if err != nil {
		return false
	}

	//Check if the scheme is empty
	if u.Scheme == "" {
		return false
	}

	//Check if the host is empty
	if u.Host == "" {
		return false
	}

	//Check if the scheme is in the list of allowed protocols
	if slices.Index(allowedProtocols, u.Scheme) == -1 {
		return false
	}

	return true
}

// Check the configuration
func checkConfiguration(config *Configuration) error {
	//Check all the required fields are present
	//Check if backend services are defined
	if config.Services == nil || len(config.Services) == 0 {
		return errors.New("services are not defined")
	}
	//Check if rules options are defined
	if config.RuleConfig == nil {
		return errors.New("rules configuration is not defined")
	}

	//Check if logging config is defined
	if config.LogConfig == nil {
		return errors.New("logging is not defined")
	}

	//Check if cranberry url is defined
	if config.CranberryURL == "" {
		return errors.New("cranberry url is not defined")
	}

	//For every service check if the necessary information exists and is correct
	for i, service := range config.Services {
		//Check the listening address
		if service.ListeningAddress == "" {
			return fmt.Errorf("listening address missing for service %d", i)
		}

		if !isValidIPAddress(service.ListeningAddress) {
			return errors.New("listening address is not valid ip address")
		}

		//Check the listening port
		if service.ListeningPort == "" {
			return fmt.Errorf("listening port missing for service %d", i)
		}

		if !isValidPort(service.ListeningPort) {
			return errors.New("listening port is not valid, should be >= 1 and <= 65535")
		}

		//Check the listening protocol
		if service.ListeningProtocol == "" {
			return fmt.Errorf("listening protocol missing for service %d", i)
		} else {
			//If the listening protocol is not in allowed protocols
			if slices.Index(allowedProtocols, strings.ToLower(service.ListeningProtocol)) == -1 {
				return fmt.Errorf("listening protocol invalid for service %d, allowed values are %v", i, allowedProtocols)
			}

			//The protocol is correct so make it lowercase
			config.Services[i].ListeningProtocol = strings.ToLower(service.ListeningProtocol)
		}

		//Check if either the remote url was specified or the combo of remote protocol, remote address and remote port
		if service.RemoteURL == "" && (service.RemoteAddress == "" || service.RemotePort == "" || service.RemoteProtocol == "") {
			return fmt.Errorf("either rurl (Remote URL) or raddress, rport and rprotocol must be specified in service %d", i)
		}

		//If the remote url is specified and the other fields are not
		if service.RemoteURL != "" && service.RemoteAddress == "" && service.RemotePort == "" && service.RemoteProtocol == "" {
			//Check if the remote url is a valid url
			if !isValidURL(service.RemoteURL) {
				return fmt.Errorf("remote url is not valid for service %d", i)
			}
		}

		//Check the remote protocol
		if service.RemoteProtocol != "" {
			//If the listening protocol is not in allowed protocols
			if slices.Index(allowedProtocols, strings.ToLower(service.RemoteProtocol)) == -1 {
				return fmt.Errorf("listening protocol invalid for service %d, allowed values are %v", i, allowedProtocols)
			}

			//The protocol is correct so make it lowercase
			config.Services[i].RemoteProtocol = strings.ToLower(service.RemoteProtocol)
		}
	}

	return nil
}

// Load the configuration from a file
func LoadConfigurationFromFile(filePath string) (*Configuration, error) {
	//Check if the file exists
	found := utils.CheckFileExists(filePath)
	if !found {
		return nil, errors.New("configuration file cannot be found")
	}
	//Open the file and load the data into the configuration structure
	file, err := os.Open(filePath)
	//Check if an error occured when opening the file
	if err != nil {
		return nil, err
	}

	//Create the configuration struct
	conf := Configuration{}

	err = conf.FromYAML(file)
	//Check if an error occured when loading the json from file
	if err != nil {
		return nil, err
	}
	//Check if there are errors in the configuration
	err = checkConfiguration(&conf)
	if err != nil {
		return nil, err
	}

	//Add the default values to fields which are not populated
	completeDefaultValues(&conf)

	return &conf, nil
}
