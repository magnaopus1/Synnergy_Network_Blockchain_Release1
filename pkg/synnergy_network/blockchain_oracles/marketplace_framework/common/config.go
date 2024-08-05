package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
)

// Config represents the configuration structure
type Config struct {
	Network   NetworkConfig   `json:"network"`
	Security  SecurityConfig  `json:"security"`
	Database  DatabaseConfig  `json:"database"`
	API       APIConfig       `json:"api"`
	Logging   LoggingConfig   `json:"logging"`
	Consensus ConsensusConfig `json:"consensus"`
}

// NetworkConfig represents network-related configurations
type NetworkConfig struct {
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	MaxConnections int    `json:"max_connections"`
}

// SecurityConfig represents security-related configurations
type SecurityConfig struct {
	EncryptionMethod string `json:"encryption_method"`
	SecretKey        string `json:"secret_key"`
}

// DatabaseConfig represents database-related configurations
type DatabaseConfig struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// APIConfig represents API-related configurations
type APIConfig struct {
	BaseURL string `json:"base_url"`
	Timeout int    `json:"timeout"`
}

// LoggingConfig represents logging-related configurations
type LoggingConfig struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

// ConsensusConfig represents consensus-related configurations
type ConsensusConfig struct {
	Algorithm  string `json:"algorithm"`
	Difficulty int    `json:"difficulty"`
}

// Configuration holds the application configuration
var (
	configuration *Config
	once          sync.Once
)

// LoadConfig loads the configuration from a file
func LoadConfig(configFile string) (*Config, error) {
	once.Do(func() {
		file, err := os.Open(configFile)
		if err != nil {
			log.Fatalf("Error opening config file: %v", err)
		}
		defer file.Close()

		bytes, err := ioutil.ReadAll(file)
		if err != nil {
			log.Fatalf("Error reading config file: %v", err)
		}

		configuration = &Config{}
		if err := json.Unmarshal(bytes, configuration); err != nil {
			log.Fatalf("Error unmarshaling config file: %v", err)
		}
	})

	if configuration == nil {
		return nil, errors.New("failed to load configuration")
	}

	return configuration, nil
}

// GetConfig returns the loaded configuration
func GetConfig() *Config {
	return configuration
}

// SaveConfig saves the current configuration to a file
func SaveConfig(configFile string) error {
	if configuration == nil {
		return errors.New("no configuration to save")
	}

	bytes, err := json.MarshalIndent(configuration, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %v", err)
	}

	if err := ioutil.WriteFile(configFile, bytes, 0644); err != nil {
		return fmt.Errorf("error writing config file: %v", err)
	}

	return nil
}

// ValidateConfig validates the loaded configuration
func ValidateConfig() error {
	if configuration == nil {
		return errors.New("configuration not loaded")
	}

	if configuration.Network.Port <= 0 {
		return errors.New("invalid network port")
	}

	if configuration.Security.SecretKey == "" {
		return errors.New("security secret key is required")
	}

	if configuration.Database.Type == "" || configuration.Database.Host == "" ||
		configuration.Database.Port <= 0 || configuration.Database.Username == "" ||
		configuration.Database.Password == "" || configuration.Database.Name == "" {
		return errors.New("invalid database configuration")
	}

	if configuration.API.BaseURL == "" || configuration.API.Timeout <= 0 {
		return errors.New("invalid API configuration")
	}

	if configuration.Logging.Level == "" || configuration.Logging.FilePath == "" {
		return errors.New("invalid logging configuration")
	}

	if configuration.Consensus.Algorithm == "" || configuration.Consensus.Difficulty <= 0 {
		return errors.New("invalid consensus configuration")
	}

	return nil
}

// LogConfig logs the current configuration
func LogConfig() {
	configBytes, err := json.MarshalIndent(configuration, "", "  ")
	if err != nil {
		log.Printf("Error marshaling configuration for logging: %v", err)
		return
	}
	log.Printf("Current Configuration: %s", string(configBytes))
}
