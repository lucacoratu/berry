package detection

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"blueberry/internal/config"
	"blueberry/internal/logging"
	"blueberry/internal/models"
	data "blueberry/internal/models"
)

var SupportedEncodings = []string{"base64", "url"}

// Loads all the rules that can be found in the specified directory
// Pass the logger as a parameter for better view of the problems
// @param rulesDirectory - the directory from which the rules should be pulled
// @param logger - the logger to be used to display the errors
// If the directory cannot be opened to read all the files in it then an error is returned
func LoadRulesFromDirectory(configuration config.Configuration, logger logging.ILogger) ([]Rule, error) {
	rulesDirectory := configuration.RuleConfig.RulesDirectory

	//Check if the directory exists
	_, err := os.Stat(rulesDirectory)
	if err != nil {
		return nil, errors.New("rules directory does not exist")
	}
	//Traverse the directory to get all the rules and append them to the list
	rulesList := make([]Rule, 0)
	err = filepath.WalkDir(rulesDirectory, func(path string, d fs.DirEntry, err error) error {
		//Check if the directory is not in the list of ignored directories from the config
		if d.IsDir() {
			if configuration.RuleConfig.IgnoreRulesDirectories != nil {
				for _, ignoreDir := range configuration.RuleConfig.IgnoreRulesDirectories {
					if ignoreDir == d.Name() {
						logger.Info("Skipped rule directory", d.Name(), ", present in list of ignored directories")
						//Skip the directory
						return filepath.SkipDir
					}
				}
			}
		}

		//If the directory entry is not a directory
		if !d.IsDir() {
			//If the file doesn't end in .yaml
			if !strings.HasSuffix(d.Name(), ".yaml") {
				logger.Warning("Skipping rule file", path, ", it is not a yaml file, check the file extension")
				return nil
			}
			//The file has .yaml extension
			//Try to load the path content into a rule structure
			rule := Rule{}
			file, err := os.Open(path)
			//Check if an error occured when opening the yaml rule file
			if err != nil {
				//Log the error
				logger.Warning("Skipping rule file", path, "could not open the file for reading", err.Error())
				return nil
			}
			err = rule.FromYAML(file)
			//Check if an error occured when loading the yaml file
			if err != nil {
				logger.Warning("Skipping rule file", path, "error when parsing", err.Error())
				return nil
			}
			//Check if the rule is valid
			err = CheckRule(rule, logger)
			if err != nil {
				//The rule is not valid
				logger.Warning("Skipping rule file", path, "error when checking rule,", err.Error())
				return nil
			}
			//Check if the rule id is not already in the list of rules
			var found bool = false
			for _, ruleElem := range rulesList {
				if ruleElem.Id == rule.Id {
					found = true
					break
				}
			}
			if found {
				logger.Warning("Skipping rule file", path, "a rule with this id already exists")
				return nil
			}

			//Apply the encodings to the matching subrules based on the global and local encodings lists
			err = HandleEncodingsField(&rule)
			if err != nil {
				logger.Warning("Skipping rule file", path, "error occured when handling encodings lists", err.Error())
				return nil
			}

			//Add the rule read from file to the list of rules
			rulesList = append(rulesList, rule)
		}
		return nil
	})
	if err != nil {
		return nil, errors.New("could not walk rules directory")
	}
	return rulesList, nil
}

// Adds the encodings field based on the definition of the encodings
// @rule - the rule to set the correct encoding fields
// Returns an error if
func HandleEncodingsField(rule *Rule) error {
	//Check if a list of encodings is specified in the info field (globally)
	//If the list of encodings is specified globally then all the subfields for searching should inherit this list of encodings
	//Otherwise each field will have it's own list of encodings or none (nil).
	if rule.Info.Encodings != nil {
		if rule.Request != nil {
			//Inherit the list of global encodings to the request headers matching rules
			for _, headersRule := range rule.Request.Headers {
				//If there is not a list of encodings specified (local encodings)
				if headersRule.Encodings == nil {
					headersRule.Encodings = rule.Info.Encodings
				}
			}

			//Inherit the list of global encodings to the request parameters matching rules
			for _, parametersRule := range rule.Request.Parameters {
				//If there is not a list of encodings specified (local encodings)
				if parametersRule.Encodings == nil {
					parametersRule.Encodings = rule.Info.Encodings
				}
			}

			//Inherit the list of global encodings to the body matching rules
			for _, bodyRule := range rule.Request.Body {
				//If there is not a list of encodings specified (local encodings)
				if bodyRule.Encodings == nil {
					bodyRule.Encodings = rule.Info.Encodings
				}
			}
		}

		if rule.Response != nil {
			//Inherit the list of global encodings to the response headers matching rules
			for _, headersRule := range rule.Response.Headers {
				//If there is not a list of encodings specified (local encodings)
				if headersRule.Encodings == nil {
					headersRule.Encodings = rule.Info.Encodings
				}
			}

			//Inherit the list of global encodings to the response body matching rules
			for _, bodyRule := range rule.Response.Body {
				//If there is not a list of encodings specified (local encodings)
				if bodyRule.Encodings == nil {
					bodyRule.Encodings = rule.Info.Encodings
				}
			}
		}

		//Inherit the global encodings to the independent fields of the rule
		if rule.Request != nil {
			if rule.Request.Method != nil {
				if rule.Request.Method.Encodings == nil {
					rule.Request.Method.Encodings = rule.Info.Encodings
				}
			}

			if rule.Request.URL != nil {
				for i, _ := range rule.Request.URL {
					if rule.Request.URL[i].Encodings == nil {
						rule.Request.URL[i].Encodings = rule.Info.Encodings
					}
				}
			}
		}

		if rule.Response != nil {
			if rule.Response.Code != nil {
				if rule.Response.Code.Encodings == nil {
					rule.Response.Code.Encodings = rule.Info.Encodings
				}
			}
		}
	}

	return nil
}

// Check if the rule information is valid or not
// @param info - the rule information structure
// Returns an error if the info field is not valid
func CheckRuleInfo(info *RuleInfo) error {
	//Check if the rule info structure is missing
	if info == nil {
		return errors.New("rule cannot have empty info")
	}

	//Check if the rule severity is one of the allowed (case insensitive) - low, medium, high, critical
	if strings.ToLower(info.Severity) != "low" && strings.ToLower(info.Severity) != "medium" && strings.ToLower(info.Severity) != "high" && strings.ToLower(info.Severity) != "critical" {
		return errors.New("rule severity cannot be something apart from: low, medium, high, critical")
	}

	//Check if the rule action is one of the allowed (case insensitive) - allow, drop
	//This should apply only if the rule action is not empty
	if info.Action != "" {
		if strings.ToLower(info.Action) != "allow" && strings.ToLower(info.Action) != "drop" {
			return errors.New("rule action cannot be something other than: allow, drop")
		}
	}

	//Check if the encodings is a list containing supported encodings
	if info.Encodings != nil {
		for _, encoding := range info.Encodings {
			var found bool = false
			for _, supportedEncoding := range SupportedEncodings {
				if strings.ToLower(encoding) == supportedEncoding {
					found = true
				}
			}

			if !found {
				return errors.New("rule encodings contains unsuported encodings, " + encoding)
			}
		}
	}

	return nil
}

// Checks if the rule is valid or not
// @param rule - the rule struct to be tested
// @param logger - the logger to be used
// Returns an error which specifies the problem with the rule
func CheckRule(rule Rule, logger logging.ILogger) error {
	//Check if the info field is valid
	if err := CheckRuleInfo(rule.Info); err != nil {
		return err
	}

	//Check if the request field exists in the rule
	if rule.Request != nil {
		//Check if the regexes specified in the rule are compiling
		//Check if the URL regex compiles
		if rule.Request.URL != nil {
			for i, _ := range rule.Request.URL {
				if _, err := regexp.Compile(rule.Request.URL[i].Regex); err != nil {
					return errors.New("cannot compile URL regex, " + err.Error())
				}
			}
		}
		//Check if the method regex compiles
		if rule.Request.Method != nil {
			if _, err := regexp.Compile(rule.Request.Method.Regex); err != nil {
				return errors.New("cannot compile Method regex, " + err.Error())
			}
		}
		//Check if the parameters regex compiles
		if rule.Request.Parameters != nil {
			for _, parameter := range rule.Request.Parameters {
				if _, err := regexp.Compile(parameter.Regex); err != nil {
					return errors.New("cannot compile regex for parameter, " + parameter.Name + ", " + err.Error())
				}
			}
		}
		//Check if the headers regex compiles
		if rule.Request.Headers != nil {
			for _, header := range rule.Request.Headers {
				if _, err := regexp.Compile(header.Regex); err != nil {
					return errors.New("cannot compile regex for header, " + header.Name + ", " + err.Error())
				}
			}
		}
		//Check if the regex for body
		if rule.Request.Body != nil {
			for _, bodyRule := range rule.Request.Body {
				if _, err := regexp.Compile(bodyRule.Regex); err != nil {
					return errors.New("cannot compile regex for the body, " + err.Error())
				}
			}
		}
	}

	//Check the websocket regexes
	if rule.Websocket != nil {
		for _, wsRule := range rule.Websocket {
			if _, err := regexp.Compile(wsRule.Regex); err != nil {
				return errors.New("cannot compile regex for websocket match, " + err.Error())
			}
			if _, err := regexp.Compile(wsRule.HexRegex); err != nil {
				return errors.New("cannot compile hexregex for websocket, " + err.Error())
			}
		}
	}

	//Check the tcp regexes
	if rule.TCP != nil {
		for _, tcpRule := range rule.TCP {
			if _, err := regexp.Compile(tcpRule.Regex); err != nil {
				return errors.New("cannot compile regex for tcp match, " + err.Error())
			}

			if _, err := regexp.Compile(tcpRule.HexRegex); err != nil {
				return errors.New("cannot compile hexregex for tcp match, " + err.Error())
			}
		}
	}

	//Check the tcp direction
	if rule.TCP != nil {
		for _, tcpRule := range rule.TCP {
			if tcpRule.Direction != "ingress" && tcpRule.Direction != "egress" {
				return errors.New("tcp rule direction can be ingress or egress")
			}
		}
	}

	//Check all the encodings fields
	if err := CheckEncodingSubfields(rule, logger); err != nil {
		return errors.New("subfield contains invalid encoding, " + err.Error())
	}

	return nil
}

// Checks if the encodings subfields (local encodings fields) are valid
// @param rule - the rule to be checked
// @param logger - the logger used by the application to better log the messages
// Returns an error if any of the subfields contains invalid encodings in the list
func CheckEncodingSubfields(rule Rule, logger logging.ILogger) error {
	//Check the request method encodings list
	if rule.Request != nil {
		if rule.Request.Method != nil {
			err := CheckEncodingsList(rule.Request.Method.Encodings)
			//Check if an error occured
			if err != nil {
				return errors.New("Invalid encodings list in request method, " + err.Error())
			}
		}

		//Check the request URL encodings list
		if rule.Request.URL != nil {
			for i, _ := range rule.Request.URL {
				err := CheckEncodingsList(rule.Request.URL[i].Encodings)
				//Check if an error occured
				if err != nil {
					return errors.New("Invalid encodings list in request URL, " + err.Error())
				}
			}
		}

		//Check the request header rules
		for _, subRule := range rule.Request.Headers {
			err := CheckEncodingsList(subRule.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in request header " + subRule.Name + ", " + err.Error())
			}
		}

		//Check the request parameters rules
		for _, subRule := range rule.Request.Parameters {
			err := CheckEncodingsList(subRule.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in request parameter " + subRule.Name + ", " + err.Error())
			}
		}

		//Check the request body rule
		for _, subRule := range rule.Request.Body {
			err := CheckEncodingsList(subRule.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in request body, " + err.Error())
			}
		}
	}

	//Check the response code encodings
	if rule.Response != nil {
		if rule.Response.Code != nil {
			err := CheckEncodingsList(rule.Response.Code.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in response code, " + err.Error())
			}
		}

		//Check the response headers encodings
		for _, subRule := range rule.Response.Headers {
			err := CheckEncodingsList(subRule.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in the response headers, " + err.Error())
			}
		}

		//Check the response body encodings
		for _, subRule := range rule.Response.Body {
			err := CheckEncodingsList(subRule.Encodings)
			if err != nil {
				return errors.New("Invalid encodings list in the response body, " + err.Error())
			}
		}
	}

	//All encodings list have the right values
	return nil
}

func CheckEncodingsList(encodings []string) error {
	for _, encoding := range encodings {
		for _, supportedEncoding := range SupportedEncodings {
			if strings.ToLower(encoding) != supportedEncoding {
				return errors.New("invalid encoding specified, " + encoding)
			}
		}
	}
	return nil
}

// Converts the severity string to integer value
// @param severity - the string format of the representation (can be low, medium, high, critical) - case insensitive
// Returns the integer coresponding to severity or -1 if the severity type does not exist
func ConvertSeverityStringToInteger(severity string) int64 {
	switch strings.ToLower(severity) {
	case "low":
		return data.LOW
	case "medium":
		return data.MEDIUM
	case "high":
		return data.HIGH
	case "critical":
		return data.CRITICAL
	default:
		return -1
	}
}

// Gets the action for a specific rule
// @param rules - the list of rules loaded from disk
// @param ruleId - the id of the rule to retrieve the action field
// Returns the action defined inside the rule (allow, drop) or empty string if no action is specified
func GetRuleAction(rules []Rule, ruleId string) string {
	for _, rule := range rules {
		if rule.Id == ruleId {
			return rule.Info.Action
		}
	}

	return ""
}

// Get the verdict based on the findings
// @param rules - the list of rules loaded from disk
// @param defaultAction - the default action specified in the rules config
// @param findings - the list of rule findings
func GetVerdictBasedOnFindings(rules []Rule, defaultAction string, findings []*models.RuleFindingData) string {
	//Loop through the findings
	for _, finding := range findings {
		//Get the rule action
		ruleAction := GetRuleAction(rules, finding.RuleId)
		//If the rule action is drop then the verdict is drop
		if ruleAction == "drop" {
			return "drop"
		}

		//if the rule action is not specified and the default action from config is drop then verdict is drop
		if ruleAction == "" && defaultAction == "drop" {
			return "drop"
		}
	}

	return "allow"
}
