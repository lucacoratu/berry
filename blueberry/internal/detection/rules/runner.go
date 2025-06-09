package detection

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"blueberry/internal/config"
	data "blueberry/internal/models"
	"blueberry/internal/utils"
	"blueberry/internal/websocket"
	"blueberry/pkg/logging"

	"github.com/mowshon/iterium"
)

// Structure which will hold all the necessary data to match the rules on the request and the response
type RuleRunner struct {
	logger        logging.ILogger
	rules         []Rule
	apiWsConn     *websocket.APIWebSocketConnection
	configuration config.Configuration
}

// Creates a new rule runner struct
func NewRuleRunner(logger logging.ILogger, rules []Rule, apiWsConn *websocket.APIWebSocketConnection, configuration config.Configuration) *RuleRunner {
	return &RuleRunner{logger: logger, rules: rules, apiWsConn: apiWsConn, configuration: configuration}
}

// Decodes the value string using the encodings of the rule
// Creates all the possible permutation of the list of encodings specified (length 1, 2 ...)
// @param value - the value to be decoded
// @param encodings - the list of encodings
// Returns the list of possible decodings of the value
func (rl *RuleRunner) decodeString(value string, encodings []string) ([]string, error) {
	//Create the return list of decoded strings
	decodedStrings := make([]string, 0)
	//The first element in the list should be the unmodified string (len 0 of the encodings permutations)
	decodedStrings = append(decodedStrings, value)

	//Check if the list of encodings is not empty
	if encodings != nil {
		//Create the list of possible permutations
		for i := 0; i < len(encodings); i++ {
			sizeIPermutations := iterium.Permutations(encodings, i)
			encPermutations, err := sizeIPermutations.Slice()
			//Check if an error occured
			if err != nil {
				//Return the original value and the error
				return decodedStrings, err
			}
			//For each permutation of the possible encodings
			for _, permutation := range encPermutations {
				//Create the result so that chained decoding can be made
				var decString string = value
				//Apply the decodings specified in the permutation
				for _, decoding := range permutation {
					//Do the correct decoding
					switch decoding {
					case "base64":
						//Decode the string from base64
						decodedString, err := base64.StdEncoding.DecodeString(decString)
						if err != nil {
							//The decoding failed from base64 so continue with the other decodings
							continue
						}
						//Update the final decoded string
						decString = string(decodedString)
					case "url":
						//Decode the string from url
						decodedString, err := url.QueryUnescape(decString)
						if err != nil {
							//The decoding failed from url so continue with other decodings
							continue
						}
						//Update the final decoded string
						decString = decodedString
					}
				}
				//Apend the decoded string to the list of decoded strings
				decodedStrings = append(decodedStrings, decString)
			}
		}
	}

	//Return the list of decoded strings using the specified encodings
	return decodedStrings, nil
}

// Searches for case insensitive match on the value or if the regex can find any matches on the given value
// @param value - the value to be searched uppon
// @param mode - the rule search specification
// Returns the list of matches it found
func (rl *RuleRunner) search(value string, mode *RuleSearchMode) []string {
	allMatches := make([]string, 0)

	//Get all the possible decodings of the value
	decodedStrings, _ := rl.decodeString(value, mode.Encodings)

	//Check if any of the decoded string matches the rule conditions
	for _, decString := range decodedStrings {
		//Check if the exact match is specified
		if mode.Match != "" {
			//Check if the value contains the match string (case insensitive)
			if strings.Contains(strings.ToLower(decString), strings.ToLower(mode.Match)) {
				//Add the match to the list of matches
				allMatches = append(allMatches, mode.Match)
			}
		}

		//Check if the regex match is specified
		if mode.Regex != "" {
			//Compile the regex
			r, err := regexp.Compile(mode.Regex)
			//Check if an error occured during the regex compilation
			if err != nil {
				rl.logger.Error("Could not the compile regex matcher from the rule, invalid regex:", mode.Regex)
				return nil
			}
			//Find all the matches for the regex
			matches := r.FindAllString(decString, -1)
			//rl.logger.Debug("Value:", value, "Regex:", mode.Regex, "Matches:", matches)
			//Check if there were any matches
			if len(matches) > 0 {
				//rl.logger.Debug("Regex,", mode.Regex, "matched on", value)
				//Add the matches to the list of matches
				allMatches = append(allMatches, matches...)
			}
		}
	}

	//Return all the matches
	return allMatches
}

// Checks if the method matches any of the rule matching specification
// @param method - the method to be searched uppon
// @param ruleMethod - the rule search specification
// Returns the list of matches or an error if something occured
func (rl *RuleRunner) checkMethod(method string, ruleMethod *RuleSearchMode) ([]string, error) {
	//Check if the rule has a method specification
	if ruleMethod == nil {
		//Return an empty list of matches
		return make([]string, 0), nil
	}
	//Search in the method for any matches
	matches := rl.search(method, ruleMethod)
	return matches, nil
}

// Checks if the URL of the request matches any of the rule matching specification
// @param url - the URL to be searched uppon
// @param ruleURL - the rule search specification
// Returns the list of matches or an error if something occured
func (rl *RuleRunner) checkURL(url string, ruleURL []*RuleSearchMode) ([]string, error) {
	//Check if the rule has a URL specification
	if ruleURL == nil {
		//Return an empty match list
		return make([]string, 0), nil
	}

	//Initialize the return list of matches
	ret_matches := make([]string, 0)

	for _, rule := range ruleURL {
		//Search in the URL path for any matches
		matches := rl.search(url, rule)
		ret_matches = append(ret_matches, matches...)
	}

	return ret_matches, nil
}

// Check if any of the header value matches a rule specification for that header name
// @param headers - the headers of the request as given by http.request package
// @param ruleURL - the rule search specification
// Returns the list of matches or an error if something occured
func (rl *RuleRunner) checkHeaders(headers map[string][]string, ruleHeaders []*HeadersRule) ([]string, error) {
	//Check if the rule has the request headers specified
	if ruleHeaders == nil {
		//Return an empty list of matches
		return make([]string, 0), nil
	}

	//Create the structure which will hold the findings list
	allMatches := make([]string, 0)

	//Loop through each header
	for headerName, headerValue := range headers {
		//Check if the header name can be found in the list of header specifications of the rule
		for _, headerSpec := range ruleHeaders {
			if headerSpec.Name == headerName {
				//Run the rule search for every value of this header
				for _, headerVal := range headerValue {
					//Call the search functions to get all the matches of the header with the rule header specifications
					matches := rl.search(headerVal, &RuleSearchMode{Match: headerSpec.Match, Regex: headerSpec.Regex, Encodings: headerSpec.Encodings})
					//Add the matches to the list of all matches
					allMatches = append(allMatches, matches...)
				}
				//Go to the next header
				break
			}
		}
	}
	return allMatches, nil
}

// Checks if any of the parameters matches a rule specification
// @param url - the URL to be searched uppon
// @param ruleURL - the rule search specification
// Returns the list of matches or an error if something occured
func (rl *RuleRunner) checkParameters(parameters map[string][]string, ruleParameters []*RequestParametersRule) ([]string, error) {
	//Check if the parameters field is specified in the rule
	if ruleParameters == nil {
		return make([]string, 0), nil
	}

	//Create the structure which will hold all the matches
	allMatches := make([]string, 0)

	//Loop through all the parameter names
	for parameterName, parameterValues := range parameters {
		//Check if the parameter name can be found in the list of parameters specified in the rule
		for _, ruleParameter := range ruleParameters {
			//If the rule parameter name is any then search through all the parameter names for a match
			if ruleParameter.Name == "any" {
				//Check all the values for a matching string
				for _, parameterValue := range parameterValues {
					matches := rl.search(parameterValue, &RuleSearchMode{Match: ruleParameter.Match, Regex: ruleParameter.Regex, Encodings: ruleParameter.Encodings})
					//Add the found matches to the list of all matches
					allMatches = append(allMatches, matches...)
				}
			} else {
				//Check if the parameter name matches the param name from the rule
				if ruleParameter.Name == parameterName {
					//Check all the values for a matching string
					for _, parameterValue := range parameterValues {
						matches := rl.search(parameterValue, &RuleSearchMode{Match: ruleParameter.Match, Regex: ruleParameter.Regex, Encodings: ruleParameter.Encodings})
						//Add the found matches to the list of all matches
						allMatches = append(allMatches, matches...)
					}
				}
			}
		}
	}

	return allMatches, nil
}

// Checks if the body of the request/response matches any rule specification for the body
// It can also check if the hash of the body (MD5 or SHA256) matches a specified hash
// @param body - the body of the request
// @param bodyRule - the list of rule specifications for the body
// Returns the list of matches, the list of hash matches or an error if something occured
func (rl *RuleRunner) checkBody(body string, bodyRule []*BodyRule) ([]string, []BodyHashMatch, error) {
	//Check if the bodyRules is not nil
	if bodyRule == nil {
		return make([]string, 0), make([]BodyHashMatch, 0), nil
	}

	//Initialize the all matches structure
	allMatches := make([]string, 0)
	//Initialize the slice which will hold all the hash matches
	allHashMatches := make([]BodyHashMatch, 0)

	//Loop through every body rule
	for _, bRule := range bodyRule {
		//Get the matches for the exact string search and regex
		matches := rl.search(body, &RuleSearchMode{Match: bRule.Match, Regex: bRule.Regex, Encodings: bRule.Encodings})
		allMatches = append(allMatches, matches...)

		//Check if the any of the hash types matches
		if bRule.MD5Sum != "" {
			//Compute the MD5 hash
			md5hasher := md5.New()
			bodyMd5 := md5hasher.Sum([]byte(body))
			//Decode the hex string of the hash from the rule
			decRuleMd5sum, err := hex.DecodeString(bRule.MD5Sum)
			//Check if an error occured
			if err != nil {
				rl.logger.Error("Could not decode md5sum from the rule", err.Error())
			} else {
				if reflect.DeepEqual(bodyMd5, decRuleMd5sum) {
					allHashMatches = append(allHashMatches, BodyHashMatch{BodyHash: bRule.MD5Sum, BodyHashAlgorithm: "MD5"})
				}
			}
		}
		if bRule.SHA256Sum != "" {
			//Compute the SHA256 sum
			bodySha256 := sha256.Sum256([]byte(body))
			hexBodySha256 := hex.EncodeToString(bodySha256[:])
			if hexBodySha256 == bRule.SHA256Sum {
				allHashMatches = append(allHashMatches, BodyHashMatch{BodyHash: bRule.SHA256Sum, BodyHashAlgorithm: "SHA256"})
			}
		}
	}

	return allMatches, allHashMatches, nil
}

// Run all the rules on the request
// @param r - the http request to operate on
// Returns a list of findings or an error if something occured
func (rl *RuleRunner) RunRulesOnRequest(r *http.Request) ([]*data.RuleFindingData, error) {
	//Create the list which will hold all the matches from all the rules for the request
	findings := make([]*data.RuleFindingData, 0)

	//Check if the rules are nil
	if rl.rules == nil {
		return findings, nil
	}

	//Loop through all the rules and check if any one of them matches a string in the request
	//TO DO... Run each rule on a different go routine
	for _, rule := range rl.rules {
		//Check if the rule has request matchers specified
		if rule.Request == nil {
			continue
		}
		allMatches := make([]string, 0)
		//Check the Method of the request
		matches, _ := rl.checkMethod(r.Method, rule.Request.Method)
		allMatches = append(allMatches, matches...)

		//Check the URL of the request
		matches, _ = rl.checkURL(r.URL.RawPath, rule.Request.URL)
		allMatches = append(allMatches, matches...)
		//Check the Headers of the request
		matches, _ = rl.checkHeaders(r.Header, rule.Request.Headers)
		allMatches = append(allMatches, matches...)
		//Check the parameters of the request
		//Check the GET parameters
		matches, _ = rl.checkParameters(r.URL.Query(), rule.Request.Parameters)
		allMatches = append(allMatches, matches...)

		//Check the POST parameters
		bodyData, err := io.ReadAll(r.Body)
		if err != nil {
			rl.logger.Error("Error occured when reading the body contents from the request in order to parse the form", err.Error())
		} else {
			//Reassign the body so other function can read the data
			r.Body = io.NopCloser(bytes.NewReader(bodyData))
		}
		//Parse the form
		err = r.ParseForm()
		//Check if an error occured
		if err != nil {
			rl.logger.Error("Error occured when parsing the request form when running rules on request", err.Error())
		} else {
			//The request has body parameters so search for matches in these.
			matches, _ := rl.checkParameters(r.PostForm, rule.Request.Parameters)
			allMatches = append(allMatches, matches...)
		}

		//Reasign the body after parsing the form
		r.Body = io.NopCloser(bytes.NewReader(bodyData))

		//Append matches to the list of findings
		for _, match := range allMatches {
			findingFound := false
			//Check if the finding is not the classification is already made for this request
			for _, finding := range findings {
				if finding.RuleId == rule.Id {
					findingFound = true
					break
				}
			}
			if findingFound {
				continue
			}

			findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: match, Length: int64(len(match))})
		}
		//Check the body of the request
		bodyData, err = io.ReadAll(r.Body)
		//Check if an error occured when getting the body data
		if err != nil {
			rl.logger.Error("Error occured when reading the body contents from the request", err.Error())
		} else {
			//Reassign the body so other function can read the data
			r.Body = io.NopCloser(bytes.NewReader(bodyData))
			matches, hashMatches, _ := rl.checkBody(string(bodyData), rule.Request.Body)
			//Add the matches to the list of findings
			for _, match := range matches {
				findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: match, Length: int64(len(match))})
			}
			//Add the hash matches to the list of matches
			for _, hashMatch := range hashMatches {
				findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Line: -1, LineIndex: -1, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: "", MatchedBodyHash: hashMatch.BodyHash, MatchedBodyHashAlg: hashMatch.BodyHashAlgorithm, Length: int64(len(hashMatch.BodyHash))})
			}
		}

		//Check if the rule has at least high severity
		if ConvertSeverityStringToInteger(rule.Info.Severity) >= data.HIGH {
			//Send an alert to the API via WebSocket
			if rl.apiWsConn != nil {
				err := rl.apiWsConn.SendRuleDetectionAlert(websocket.RuleDetectionAlert{AgentId: rl.configuration.UUID, RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: rule.Info.Severity, Timestamp: time.Now().Unix()})
				//Check if an error occured when sending the alert
				if err != nil {
					rl.logger.Error("Error occured when sending alert to API when a high or critical payload was detected")
				}
			}
		}
	}

	//Dump the request
	rawRequest, err := utils.DumpHTTPRequest(r)
	//Check if an error occured when dumping the request
	if err != nil {
		rl.logger.Error("Error occured when dumping the request to raw string", err.Error())
		return nil, err
	}

	//Look for every match in the raw request to find the line number, line offset of the match
	for _, finding := range findings {
		//Check if this finding is not a hash match
		if finding.Line != -1 && finding.LineIndex != -1 {
			lineNumber, lineOffset, err := utils.FindFindingDataInRawdata(string(rawRequest), finding.MatchedString)
			//Check if an error occures
			if err != nil {
				//Skip the match
				rl.logger.Error("Skipping match,", finding.MatchedString, "error occured when searching for the match in the raw request", err.Error())
				continue
			}
			finding.Line = lineNumber
			finding.LineIndex = lineOffset
			//rl.logger.Debug(*finding)
		}
	}

	return findings, nil
}

// Run all the rules on the response
// @param r - the http response to operate on
// Returns a list of findings or an error if something occured
func (rl *RuleRunner) RunRulesOnResponse(r *http.Response) ([]*data.RuleFindingData, error) {
	//Create the list which will hold all the matches from all the rules for the request
	findings := make([]*data.RuleFindingData, 0)

	//Check if the rules are nil
	if rl.rules == nil {
		return findings, nil
	}

	//Loop through all the rules and check if any one of them matches a string in the request
	for _, rule := range rl.rules {
		//Check if the rule has request matchers specified
		if rule.Response == nil {
			continue
		}

		allMatches := make([]string, 0)
		//Check the Headers of the request
		matches, _ := rl.checkHeaders(r.Header, rule.Response.Headers)
		allMatches = append(allMatches, matches...)

		//Append matches to the list of findings
		for _, match := range allMatches {
			findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: match, Length: int64(len(match))})
		}

		//Check the body of the request
		bodyData, err := io.ReadAll(r.Body)
		//Check if an error occured when getting the body data
		if err != nil {
			rl.logger.Error("Error occured when reading the body contents from the request", err.Error())
		} else {
			//Reassign the body so other function can read the data
			r.Body = io.NopCloser(bytes.NewReader(bodyData))
			matches, hashMatches, _ := rl.checkBody(string(bodyData), rule.Response.Body)
			//Add the matches to the list of findings
			for _, match := range matches {
				findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: match, Length: int64(len(match))})
			}
			//Add the hash matches to the list of matches
			for _, hashMatch := range hashMatches {
				findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Line: -1, LineIndex: -1, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: "", MatchedBodyHash: hashMatch.BodyHash, MatchedBodyHashAlg: hashMatch.BodyHashAlgorithm, Length: int64(len(hashMatch.BodyHash))})
			}
		}
	}

	//Dump the request
	rawResponse, err := utils.DumpHTTPResponse(r)
	//Check if an error occured when dumping the request
	if err != nil {
		rl.logger.Error("Error occured when dumping the request to raw string", err.Error())
		return nil, err
	}

	//Look for every match in the raw request to find the line number, line offset of the match
	for _, finding := range findings {
		//Check if this finding is not a hash match
		if finding.Line != -1 && finding.LineIndex != -1 {
			lineNumber, lineOffset, err := utils.FindFindingDataInRawdata(string(rawResponse), finding.MatchedString)
			//Check if an error occures
			if err != nil {
				//Skip the match
				rl.logger.Error("Skipping match,", finding.MatchedString, "error occured when searching for the match in the raw request", err.Error())
				continue
			}
			finding.Line = lineNumber
			finding.LineIndex = lineOffset
			//rl.logger.Debug(*finding)
		}
	}

	return findings, nil
}

// Searches for hex match on the value or if the regex can find any hex matches on the given value
// @param value - the value to be searched uppon (as hex)
// @param mode - the rule search specification
// Returns the list of matches it found
func (rl *RuleRunner) searchHex(value []byte, mode *RuleHexSearchMod) []string {
	allMatches := make([]string, 0)

	//Check if the exact match is specified
	if mode.Match != "" {
		//Check if the value as hex contains the match string
		if strings.Contains(strings.ToLower(hex.EncodeToString(value)), strings.ToLower(mode.Match)) {
			//Add the match to the list of matches
			allMatches = append(allMatches, mode.Match)
		}
	}

	//Check if the regex match is specified
	if mode.Regex != "" {
		//Compile the regex
		r, err := regexp.Compile(mode.Regex)

		//Check if an error occured during the regex compilation
		if err != nil {
			rl.logger.Error("Could not the compile regex matcher from the rule, invalid regex:", mode.Regex)
			return nil
		}
		//Find all the matches for the regex
		matches := r.FindAllString(strings.ToLower(hex.EncodeToString(value)), -1)
		//rl.logger.Debug("Value:", value, "Regex:", mode.Regex, "Matches:", matches)
		//Check if there were any matches
		if len(matches) > 0 {
			//rl.logger.Debug("Regex,", mode.Regex, "matched on", value)
			//Add the matches to the list of matches
			allMatches = append(allMatches, matches...)
		}
	}

	//Return all the matches
	return allMatches
}

// Run the rules on the websocket message
func (rl *RuleRunner) RunRulesOnWebsocketMessage(messageType int, messageText []byte) ([]*data.RuleFindingData, error) {
	//Create the list which will hold all the matches from all the rules for the request
	findings := make([]*data.RuleFindingData, 0)

	//Check if the rules are nil
	if rl.rules == nil {
		return findings, nil
	}

	//Loop through all the rules and check if any one of them matches a string in the request
	//TO DO... Run each rule on a different go routine
	for _, rule := range rl.rules {
		//Create the list of all matches
		allMatches := make([]string, 0)

		//Check if the rule has request matchers specified
		if rule.Websocket == nil {
			continue
		}

		for _, ws_rule := range rule.Websocket {
			//Check if the message is text
			if messageType == 1 {
				matches := rl.search(string(messageText), &RuleSearchMode{Match: ws_rule.Match, Regex: ws_rule.Regex, Encodings: nil})
				allMatches = append(allMatches, matches...)
			}

			//Check if the message is binary and apply the hex search
			if messageType == 2 {
				matches := rl.searchHex(messageText, &RuleHexSearchMod{Match: ws_rule.Match, Regex: ws_rule.Regex})
				allMatches = append(allMatches, matches...)
			}
		}

		//Append matches to the list of findings
		for _, match := range allMatches {
			findingFound := false
			//Check if the finding is not the classification is already made for this request
			for _, finding := range findings {
				if finding.RuleId == rule.Id {
					findingFound = true
					break
				}
			}

			if findingFound {
				continue
			}

			findings = append(findings, &data.RuleFindingData{RuleId: rule.Id, RuleName: rule.Info.Name, RuleDescription: rule.Info.Description, Classification: rule.Info.Classification, Severity: ConvertSeverityStringToInteger(rule.Info.Severity), MatchedString: match, Length: int64(len(match)), Line: -1, LineIndex: -1})
		}
	}

	return findings, nil
}
