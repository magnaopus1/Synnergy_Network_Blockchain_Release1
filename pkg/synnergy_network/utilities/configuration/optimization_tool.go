package configuration

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/synthron_blockchain/pkg/layer0/utilities/encryption_utils"
)

// OptimizationToolConfig represents the configuration for the optimization tool
type OptimizationToolConfig struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	OptimizationLevel int    `json:"optimization_level"`
	Enabled          bool   `json:"enabled"`
}

// OptimizationTool manages the optimization configuration
type OptimizationTool struct {
	tools map[string]*OptimizationToolConfig
	mutex sync.RWMutex
}

// NewOptimizationTool creates a new instance of OptimizationTool
func NewOptimizationTool() *OptimizationTool {
	return &OptimizationTool{
		tools: make(map[string]*OptimizationToolConfig),
	}
}

// AddTool adds a new optimization tool configuration
func (ot *OptimizationTool) AddTool(config *OptimizationToolConfig) error {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()

	if _, exists := ot.tools[config.Name]; exists {
		return errors.New("optimization tool already exists")
	}

	ot.tools[config.Name] = config
	log.Printf("Optimization tool %s added\n", config.Name)

	return nil
}

// UpdateTool updates an existing optimization tool configuration
func (ot *OptimizationTool) UpdateTool(config *OptimizationToolConfig) error {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()

	if _, exists := ot.tools[config.Name]; !exists {
		return errors.New("optimization tool does not exist")
	}

	ot.tools[config.Name] = config
	log.Printf("Optimization tool %s updated\n", config.Name)

	return nil
}

// RemoveTool removes an optimization tool configuration
func (ot *OptimizationTool) RemoveTool(name string) error {
	ot.mutex.Lock()
	defer ot.mutex.Unlock()

	if _, exists := ot.tools[name]; !exists {
		return errors.New("optimization tool does not exist")
	}

	delete(ot.tools, name)
	log.Printf("Optimization tool %s removed\n", name)

	return nil
}

// GetTool retrieves an optimization tool configuration by name
func (ot *OptimizationTool) GetTool(name string) (*OptimizationToolConfig, error) {
	ot.mutex.RLock()
	defer ot.mutex.RUnlock()

	config, exists := ot.tools[name]
	if !exists {
		return nil, errors.New("optimization tool not found")
	}

	return config, nil
}

// ListTools lists all available optimization tool configurations
func (ot *OptimizationTool) ListTools() []*OptimizationToolConfig {
	ot.mutex.RLock()
	defer ot.mutex.RUnlock()

	var configs []*OptimizationToolConfig
	for _, config := range ot.tools {
		configs = append(configs, config)
	}

	return configs
}

// ValidateToolConfig validates the optimization tool configuration parameters
func ValidateToolConfig(config *OptimizationToolConfig) error {
	if config.Name == "" {
		return errors.New("tool name is required")
	}
	if config.Type == "" {
		return errors.New("tool type is required")
	}
	if config.OptimizationLevel < 0 || config.OptimizationLevel > 10 {
		return errors.New("optimization level must be between 0 and 10")
	}
	return nil
}

// EncryptToolConfig encrypts the configuration for a given tool
func (ot *OptimizationTool) EncryptToolConfig(toolName string, encryptionKey string) ([]byte, error) {
	ot.mutex.RLock()
	defer ot.mutex.RUnlock()

	config, exists := ot.tools[toolName]
	if !exists {
		return nil, errors.New("tool not found")
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	encryptedConfig, err := encryption_utils.Encrypt(configBytes, encryptionKey)
	if err != nil {
		return nil, err
	}

	return encryptedConfig, nil
}

// DecryptToolConfig decrypts the configuration for a given tool
func (ot *OptimizationTool) DecryptToolConfig(encryptedConfig []byte, encryptionKey string) (*OptimizationToolConfig, error) {
	decryptedConfig, err := encryption_utils.Decrypt(encryptedConfig, encryptionKey)
	if err != nil {
		return nil, err
	}

	var config OptimizationToolConfig
	if err := json.Unmarshal(decryptedConfig, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// InitOptimizationTool initializes the OptimizationTool with initial configurations
func InitOptimizationTool(initialConfigs []*OptimizationToolConfig) (*OptimizationTool, error) {
	tool := NewOptimizationTool()

	for _, config := range initialConfigs {
		if err := ValidateToolConfig(config); err != nil {
			return nil, err
		}

		if err := tool.AddTool(config); err != nil {
			return nil, err
		}
	}

	return tool, nil
}

// Example of usage
func main() {
	// Example configurations
	configs := []*OptimizationToolConfig{
		{
			Name:             "GasOptimizer",
			Type:             "Gas",
			OptimizationLevel: 8,
			Enabled:          true,
		},
		{
			Name:             "StateChannelOptimizer",
			Type:             "StateChannel",
			OptimizationLevel: 7,
			Enabled:          true,
		},
	}

	// Initialize optimization tool
	tool, err := InitOptimizationTool(configs)
	if err != nil {
		log.Fatalf("Failed to initialize optimization tool: %v", err)
	}

	// List tools
	tools := tool.ListTools()
	for _, t := range tools {
		fmt.Printf("Tool: %s, Type: %s, Optimization Level: %d, Enabled: %v\n", t.Name, t.Type, t.OptimizationLevel, t.Enabled)
	}
}
