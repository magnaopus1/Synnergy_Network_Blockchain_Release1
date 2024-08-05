// Package node_configuration provides tools for configuring the nodes in the Synnergy Network.
package node_configuration

import (
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "sync"
    "time"

    "gopkg.in/yaml.v2"
)

// NetworkParameters holds various parameters for the network configuration.
type NetworkParameters struct {
    BlockTime       int           `yaml:"block_time"`       // Block time in seconds
    EpochDuration   int           `yaml:"epoch_duration"`   // Epoch duration in blocks
    StakeThreshold  int           `yaml:"stake_threshold"`  // Minimum stake required for validators
    MaxValidators   int           `yaml:"max_validators"`   // Maximum number of validators in the network
    MinValidators   int           `yaml:"min_validators"`   // Minimum number of validators in the network
    NetworkID       string        `yaml:"network_id"`       // Unique identifier for the network
    GenesisTime     time.Time     `yaml:"genesis_time"`     // Genesis block time
    ConsensusType   string        `yaml:"consensus_type"`   // Type of consensus algorithm
    InitialValidators []string    `yaml:"initial_validators"` // List of initial validators
}

// Validate checks if the network parameters are valid.
func (params *NetworkParameters) Validate() error {
    if params.BlockTime <= 0 {
        return errors.New("BlockTime must be greater than zero")
    }
    if params.EpochDuration <= 0 {
        return errors.New("EpochDuration must be greater than zero")
    }
    if params.StakeThreshold < 0 {
        return errors.New("StakeThreshold cannot be negative")
    }
    if params.MaxValidators <= 0 {
        return errors.New("MaxValidators must be greater than zero")
    }
    if params.MinValidators <= 0 || params.MinValidators > params.MaxValidators {
        return errors.New("MinValidators must be greater than zero and less than or equal to MaxValidators")
    }
    if params.NetworkID == "" {
        return errors.New("NetworkID cannot be empty")
    }
    if params.ConsensusType == "" {
        return errors.New("ConsensusType cannot be empty")
    }
    if len(params.InitialValidators) == 0 {
        return errors.New("InitialValidators cannot be empty")
    }
    return nil
}

// LoadNetworkParameters loads network parameters from a YAML file.
func LoadNetworkParameters(path string) (*NetworkParameters, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read network parameters file: %v", err)
    }

    var params NetworkParameters
    if err := yaml.Unmarshal(data, &params); err != nil {
        return nil, fmt.Errorf("failed to unmarshal network parameters: %v", err)
    }

    if err := params.Validate(); err != nil {
        return nil, fmt.Errorf("invalid network parameters: %v", err)
    }

    return &params, nil
}

// SaveNetworkParameters saves network parameters to a YAML file.
func SaveNetworkParameters(params *NetworkParameters, path string) error {
    if err := params.Validate(); err != nil {
        return fmt.Errorf("invalid network parameters: %v", err)
    }

    data, err := yaml.Marshal(params)
    if err != nil {
        return fmt.Errorf("failed to marshal network parameters: %v", err)
    }

    if err := ioutil.WriteFile(path, data, 0644); err != nil {
        return fmt.Errorf("failed to write network parameters file: %v", err)
    }

    return nil
}

// InitializeNetworkParameters initializes network parameters with default values.
func InitializeNetworkParameters() *NetworkParameters {
    return &NetworkParameters{
        BlockTime:       10,
        EpochDuration:   1000,
        StakeThreshold:  1000,
        MaxValidators:   100,
        MinValidators:   10,
        NetworkID:       "synnergy_testnet_1",
        GenesisTime:     time.Now(),
        ConsensusType:   "PoS",
        InitialValidators: []string{"validator1", "validator2", "validator3"},
    }
}

// UpdateNetworkParameters updates the network parameters in the specified file.
func UpdateNetworkParameters(path string, updates map[string]interface{}) error {
    params, err := LoadNetworkParameters(path)
    if err != nil {
        return err
    }

    for key, value := range updates {
        switch key {
        case "block_time":
            params.BlockTime = value.(int)
        case "epoch_duration":
            params.EpochDuration = value.(int)
        case "stake_threshold":
            params.StakeThreshold = value.(int)
        case "max_validators":
            params.MaxValidators = value.(int)
        case "min_validators":
            params.MinValidators = value.(int)
        case "network_id":
            params.NetworkID = value.(string)
        case "genesis_time":
            params.GenesisTime = value.(time.Time)
        case "consensus_type":
            params.ConsensusType = value.(string)
        case "initial_validators":
            params.InitialValidators = value.([]string)
        default:
            return fmt.Errorf("unknown parameter: %s", key)
        }
    }

    return SaveNetworkParameters(params, path)
}

// PrintNetworkParameters prints the network parameters in a human-readable format.
func PrintNetworkParameters(params *NetworkParameters) {
    fmt.Printf("Network Parameters:\n")
    fmt.Printf("  Block Time:       %d seconds\n", params.BlockTime)
    fmt.Printf("  Epoch Duration:   %d blocks\n", params.EpochDuration)
    fmt.Printf("  Stake Threshold:  %d\n", params.StakeThreshold)
    fmt.Printf("  Max Validators:   %d\n", params.MaxValidators)
    fmt.Printf("  Min Validators:   %d\n", params.MinValidators)
    fmt.Printf("  Network ID:       %s\n", params.NetworkID)
    fmt.Printf("  Genesis Time:     %s\n", params.GenesisTime.Format(time.RFC3339))
    fmt.Printf("  Consensus Type:   %s\n", params.ConsensusType)
    fmt.Printf("  Initial Validators: %v\n", params.InitialValidators)
}

