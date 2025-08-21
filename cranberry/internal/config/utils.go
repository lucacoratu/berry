package config

import (
	"cranberry/internal/utils"
	"errors"
	"os"
)

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

	// //Check if there are errors in the configuration
	// err = checkConfiguration(&conf)
	// if err != nil {
	// 	return nil, err
	// }

	// //Add the default values to fields which are not populated
	// completeDefaultValues(&conf)

	return &conf, nil
}
