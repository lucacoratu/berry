package utils

import (
	"bufio"
	"errors"
	"os"
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
