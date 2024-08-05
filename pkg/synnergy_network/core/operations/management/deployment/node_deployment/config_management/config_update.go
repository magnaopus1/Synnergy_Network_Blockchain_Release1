package config_management

import (
    "fmt"
    "os"
    "os/exec"
    "log"
    "io/ioutil"
    "encoding/json"
    "path/filepath"
    "sync"
)

// Configuration structure to hold the details of the configurations
type Configuration struct {
    Name        string `json:"name"`
    Version     string `json:"version"`
    Parameters  map[string]string `json:"parameters"`
    LastUpdated string `json:"last_updated"`
}

var configDir = "/etc/synnergy_network/configs"
var configs map[string]Configuration
var mu sync.Mutex

// Initialize the configuration management system
func init() {
    configs = make(map[string]Configuration)
    loadAllConfigs()
}

// Load all configurations from the configuration directory
func loadAllConfigs() {
    files, err := ioutil.ReadDir(configDir)
    if err != nil {
        log.Fatalf("Failed to read config directory: %v", err)
    }

    for _, file := range files {
        if filepath.Ext(file.Name()) == ".json" {
            loadConfig(file.Name())
        }
    }
}

// Load a single configuration from a file
func loadConfig(filename string) {
    mu.Lock()
    defer mu.Unlock()

    filePath := filepath.Join(configDir, filename)
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        log.Printf("Failed to read config file %s: %v", filename, err)
        return
    }

    var config Configuration
    if err := json.Unmarshal(data, &config); err != nil {
        log.Printf("Failed to unmarshal config file %s: %v", filename, err)
        return
    }

    configs[config.Name] = config
}

// Save a configuration to a file
func saveConfig(config Configuration) error {
    mu.Lock()
    defer mu.Unlock()

    filePath := filepath.Join(configDir, config.Name + ".json")
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %v", err)
    }

    if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
        return fmt.Errorf("failed to write config file %s: %v", filePath, err)
    }

    return nil
}

// Update the configuration parameters and save the updated configuration
func UpdateConfig(name string, parameters map[string]string) error {
    mu.Lock()
    config, exists := configs[name]
    mu.Unlock()

    if !exists {
        return fmt.Errorf("configuration %s not found", name)
    }

    for key, value := range parameters {
        config.Parameters[key] = value
    }

    config.LastUpdated = currentTimestamp()

    if err := saveConfig(config); err != nil {
        return fmt.Errorf("failed to save updated configuration: %v", err)
    }

    reloadConfig(name)
    return nil
}

// Reload the configuration by applying it to the system
func reloadConfig(name string) {
    config, exists := configs[name]
    if !exists {
        log.Printf("Configuration %s not found for reloading", name)
        return
    }

    switch config.Name {
    case "node":
        reloadNodeConfig(config)
    case "network":
        reloadNetworkConfig(config)
    default:
        log.Printf("Unknown configuration type: %s", config.Name)
    }
}

// Reload the node configuration
func reloadNodeConfig(config Configuration) {
    // Apply the node configuration changes here
    // Example: Restarting the node service to apply new configurations
    cmd := exec.Command("systemctl", "restart", "synnergy-node")
    if err := cmd.Run(); err != nil {
        log.Printf("Failed to restart node service: %v", err)
    } else {
        log.Println("Node service restarted successfully")
    }
}

// Reload the network configuration
func reloadNetworkConfig(config Configuration) {
    // Apply the network configuration changes here
    // Example: Restarting the network service to apply new configurations
    cmd := exec.Command("systemctl", "restart", "synnergy-network")
    if err := cmd.Run(); err != nil {
        log.Printf("Failed to restart network service: %v", err)
    } else {
        log.Println("Network service restarted successfully")
    }
}

// Helper function to get the current timestamp
func currentTimestamp() string {
    return fmt.Sprintf("%d", time.Now().Unix())
}

// List all configurations
func ListConfigs() []Configuration {
    mu.Lock()
    defer mu.Unlock()

    configsList := make([]Configuration, 0, len(configs))
    for _, config := range configs {
        configsList = append(configsList, config)
    }
    return configsList
}

// Get configuration details by name
func GetConfig(name string) (Configuration, error) {
    mu.Lock()
    defer mu.Unlock()

    config, exists := configs[name]
    if !exists {
        return Configuration{}, fmt.Errorf("configuration %s not found", name)
    }
    return config, nil
}

// Add a new configuration
func AddConfig(config Configuration) error {
    mu.Lock()
    defer mu.Unlock()

    if _, exists := configs[config.Name]; exists {
        return fmt.Errorf("configuration %s already exists", config.Name)
    }

    configs[config.Name] = config
    return saveConfig(config)
}

// Delete a configuration
func DeleteConfig(name string) error {
    mu.Lock()
    defer mu.Unlock()

    if _, exists := configs[name]; !exists {
        return fmt.Errorf("configuration %s not found", name)
    }

    delete(configs, name)
    filePath := filepath.Join(configDir, name + ".json")
    if err := os.Remove(filePath); err != nil {
        return fmt.Errorf("failed to delete config file %s: %v", filePath, err)
    }

    return nil
}
