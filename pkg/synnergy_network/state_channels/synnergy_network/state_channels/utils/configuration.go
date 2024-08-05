package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// Configuration represents the structure of the configuration file
type Configuration struct {
	NetworkID        string `json:"network_id"`
	BlockTime        int    `json:"block_time"`
	ConsensusAlgo    string `json:"consensus_algo"`
	EncryptionMethod string `json:"encryption_method"`
	DatabaseURL      string `json:"database_url"`
}

var (
	config *Configuration
	once   sync.Once
)

// LoadConfiguration loads the configuration from a file
func LoadConfiguration(filePath string) (*Configuration, error) {
	once.Do(func() {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("Error opening config file: %v\n", err)
			return
		}
		defer file.Close()

		byteValue, _ := ioutil.ReadAll(file)

		config = &Configuration{}
		if err := json.Unmarshal(byteValue, config); err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
		}
	})

	return config, nil
}

// GetConfiguration returns the loaded configuration
func GetConfiguration() *Configuration {
	if config == nil {
		panic("Configuration not loaded")
	}
	return config
}
