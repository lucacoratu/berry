package utils

import (
	"blueberry/internal/models"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
)

// Check if the filepath is valid and exists on the disk
func CheckFileExists(filePath string) bool {
	//Get the current directory
	//pwd, _ := os.Getwd()
	//Check if the file exists
	_, err := os.Stat(filePath)
	//Return the result
	return !os.IsNotExist(err)
}

// Read all data from a file in a single string
func ReadAllDataFromFile(filePath string) (string, error) {
	fileData, err := os.ReadFile(filePath)
	return string(fileData), err
}

// Read all lines in the file
func ReadLinesFromFile(filePath string) ([]string, error) {
	//Get the current directory
	//pwd, _ := os.Getwd()
	//Check if the file exists
	exists := CheckFileExists(filePath)
	if !exists {
		return nil, errors.New("file does not exist")
	}
	//Open the file
	file, err := os.Open(filePath)
	//Check if an error occured when opening the file
	if err != nil {
		return nil, err
	}
	//Close the file at the end of the function
	defer file.Close()

	//Read lines from the file and append it to returning splice
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	lines := []string{}
	for fileScanner.Scan() {
		lines = append(lines, fileScanner.Text())
	}
	//Return the lines
	return lines, nil
}

// Check connection to the collector
func CheckAPIConnection(apiBaseURL string) bool {
	response, err := http.Get(apiBaseURL + "/healthcheck")
	if err != nil {
		return false
	}

	if response.StatusCode != http.StatusOK {
		return false
	}
	return true
}

// Collects information about the machine
func GetMachineInfo() (models.MachineInformation, error) {
	machineInfo := models.MachineInformation{}
	//Get the operating system
	machineInfo.OS = runtime.GOOS
	//Get the hostname of the machine
	hostname, err := os.Hostname()
	if err != nil {
		return machineInfo, errors.New("cannot get the hostname of the machine, " + err.Error())
	}
	machineInfo.Hostname = hostname
	//Get the ip addresses on all network interfaces
	ifaces, err := net.Interfaces()
	//Check if an error occured when getting the network interfaces of the machine
	if err != nil {
		return machineInfo, errors.New("cannot get the network interfaces of the machine, " + err.Error())
	}

	//Go through all the network interfaces and add
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// process IP address
			if !ip.IsLoopback() {
				machineInfo.IPAddresses = append(machineInfo.IPAddresses, ip.String())
			}
		}
	}
	return machineInfo, nil
}

// Dumps the http request as a string
func DumpHTTPRequest(req *http.Request) ([]byte, error) {
	//Create the first line of the request which contains the method, url path and the version of http
	rawRequest := make([]byte, 0)
	rawRequest = append(rawRequest, []byte(req.Method)...)
	rawRequest = append(rawRequest, ' ')
	rawRequest = append(rawRequest, []byte(req.URL.Path)...)
	if len(req.URL.Query()) > 0 {
		rawRequest = append(rawRequest, '?')
	}
	rawRequest = append(rawRequest, []byte(req.URL.RawQuery)...)
	rawRequest = append(rawRequest, ' ')
	rawRequest = append(rawRequest, []byte(req.Proto)...)
	rawRequest = append(rawRequest, '\n')
	//Add the Host header
	rawRequest = append(rawRequest, []byte("Host: "+req.Host)...)
	rawRequest = append(rawRequest, '\n')
	//Add all the headers and their values
	// Loop over header names
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		//Append the name
		rawRequest = append(rawRequest, []byte(key)...)
		rawRequest = append(rawRequest, ':')
		rawRequest = append(rawRequest, ' ')
		// Loop over all values for the name.
		for _, value := range req.Header[key] {
			rawRequest = append(rawRequest, []byte(value)...)
			if len(req.Header[key]) > 1 {
				rawRequest = append(rawRequest, ';')
			}
		}
		rawRequest = append(rawRequest, '\n')
	}
	//Add 1 new line (RFC 2616)
	rawRequest = append(rawRequest, '\n')
	//Add the request body
	//Read the data from the body
	bodyData, err := io.ReadAll(req.Body)
	//Check if the body could have been read
	if err != nil {
		return rawRequest, errors.New("could not read the request body")
	}

	//Reassign the body so other function can read the data
	req.Body = io.NopCloser(bytes.NewReader(bodyData))
	fmt.Println(bodyData)
	//bodyData, _ = io.ReadAll(req.Body)

	rawRequest = append(rawRequest, bodyData...)
	//fmt.Println(bodyData)
	return rawRequest, nil
}

// Dumps the http response as a string
func DumpHTTPResponse(res *http.Response) ([]byte, error) {
	if res == nil {
		return nil, errors.New("response is nil")
	}

	//Create the first line of the response which contains the version, status code and the status message
	rawResponse := make([]byte, 0)
	//Add the response protocol version
	rawResponse = append(rawResponse, []byte(res.Proto)...)
	rawResponse = append(rawResponse, ' ')
	// //Add the status code
	// rawResponse = append(rawResponse, []byte(strconv.Itoa(res.StatusCode))...)
	// rawResponse = append(rawResponse, ' ')
	//Add the status message
	rawResponse = append(rawResponse, []byte(res.Status)...)
	rawResponse = append(rawResponse, '\n')
	//Add the Host header
	// rawResponse = append(rawResponse, []byte("Host: "+res.Request.Host)...)
	// rawResponse = append(rawResponse, '\n')
	//Add all the headers and their values
	// Loop over header names
	keys := make([]string, 0, len(res.Header))
	for k := range res.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		//Append the name
		rawResponse = append(rawResponse, []byte(key)...)
		rawResponse = append(rawResponse, ':')
		rawResponse = append(rawResponse, ' ')
		// Loop over all values for the name.
		for _, value := range res.Header[key] {
			rawResponse = append(rawResponse, []byte(value)...)
			if len(res.Header[key]) > 1 {
				rawResponse = append(rawResponse, ';')
			}
		}
		rawResponse = append(rawResponse, '\n')
	}
	//Add 1 new line (RFC 2616)
	rawResponse = append(rawResponse, '\n')
	//Add the request body
	//Read the data from the body
	bodyData, err := io.ReadAll(res.Body)

	//Reassign the body so other function can read the data
	res.Body = io.NopCloser(bytes.NewReader(bodyData))

	//Check if the body could have been read
	if err != nil {
		return rawResponse, errors.New("could not read the response body")
	}
	rawResponse = append(rawResponse, bodyData...)
	return rawResponse, nil
}

func FindFindingDataInRequest(req *http.Request, searchString string) (int64, int64, error) {
	var lineIndex int = 0

	//Dump the HTTP request to string
	requestData, err := DumpHTTPRequest(req)
	//Check if an error occured when dumping the HTTP request to string
	if err != nil {
		return -1, -1, err
	}

	//Get the lines of the request
	requestLines := strings.Split(string(requestData), "\n")

	//Loop through all the request lines and find the one which has the searched string
	for index, line := range requestLines {
		lineIndex = strings.Index(line, searchString)
		//fmt.Println(searchString, index, lineIndex)
		if lineIndex != -1 {
			return int64(index), int64(lineIndex), nil
		}
	}

	return -1, -1, nil
}

func FindFindingDataInRawdata(rawData string, searchString string) (int64, int64, error) {
	var lineIndex int = 0
	//Get the lines of the raw data
	requestLines := strings.Split(rawData, "\n")

	//Loop through all the request lines and find the one which has the searched string
	for index, line := range requestLines {
		lineIndex = strings.Index(strings.ToLower(line), strings.ToLower(searchString))
		//If the searched string was found then return the line and the line offset
		if lineIndex != -1 {
			return int64(index), int64(lineIndex), nil
		}
	}

	//The string was not found
	return -1, -1, nil
}
