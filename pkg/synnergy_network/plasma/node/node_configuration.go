package node

import (
    "encoding/json"
    "errors"
    "io/ioutil"
    "os"
    "sync"
)

// NodeConfig represents the configuration of a node
type NodeConfig struct {
    NodeID           string `json:"node_id"`
    Address          string `json:"address"`
    Port             string `json:"port"`
    Consensus        string `json:"consensus"`
    Difficulty       int    `json:"difficulty"`
    Stake            int    `json:"stake"`
    ValidatorAddress string `json:"validator_address"`
}

// Node represents a node in the blockchain network
type Node struct {
    Blockchain       []Block
    Nodes            map[string]*Node
    PendingTxns      []child_chain.Transaction
    Consensus        string
    Difficulty       int
    mu               sync.Mutex
    NodeID           string
    Stake            int
    ValidatorSet     map[string]int
    ValidatorAddress string
    Address          string
    Port             string
}

// NewNode creates a new Node from the given configuration
func NewNodeFromConfig(config NodeConfig) *Node {
    return &Node{
        Blockchain:       []Block{},
        Nodes:            make(map[string]*Node),
        PendingTxns:      []child_chain.Transaction{},
        Consensus:        config.Consensus,
        Difficulty:       config.Difficulty,
        NodeID:           config.NodeID,
        Stake:            config.Stake,
        ValidatorSet:     make(map[string]int),
        ValidatorAddress: config.ValidatorAddress,
        Address:          config.Address,
        Port:             config.Port,
    }
}

// SaveConfig saves the node configuration to a file
func (n *Node) SaveConfig(filename string) error {
    config := NodeConfig{
        NodeID:           n.NodeID,
        Address:          n.Address,
        Port:             n.Port,
        Consensus:        n.Consensus,
        Difficulty:       n.Difficulty,
        Stake:            n.Stake,
        ValidatorAddress: n.ValidatorAddress,
    }

    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(filename, data, 0644)
}

// LoadConfig loads the node configuration from a file
func LoadConfig(filename string) (NodeConfig, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return NodeConfig{}, err
    }

    var config NodeConfig
    err = json.Unmarshal(data, &config)
    if err != nil {
        return NodeConfig{}, err
    }

    return config, nil
}

// UpdateConfig updates the node configuration
func (n *Node) UpdateConfig(config NodeConfig) error {
    n.mu.Lock()
    defer n.mu.Unlock()

    if config.NodeID != "" {
        n.NodeID = config.NodeID
    }
    if config.Address != "" {
        n.Address = config.Address
    }
    if config.Port != "" {
        n.Port = config.Port
    }
    if config.Consensus != "" {
        n.Consensus = config.Consensus
    }
    if config.Difficulty != 0 {
        n.Difficulty = config.Difficulty
    }
    if config.Stake != 0 {
        n.Stake = config.Stake
    }
    if config.ValidatorAddress != "" {
        n.ValidatorAddress = config.ValidatorAddress
    }

    return nil
}

// LoadOrCreateConfig loads the node configuration from a file or creates a new one if it does not exist
func LoadOrCreateConfig(filename string, defaultConfig NodeConfig) (*Node, error) {
    config, err := LoadConfig(filename)
    if err != nil {
        if os.IsNotExist(err) {
            config = defaultConfig
            if err := SaveConfig(filename, config); err != nil {
                return nil, err
            }
        } else {
            return nil, err
        }
    }

    return NewNodeFromConfig(config), nil
}

// SaveConfig saves the given configuration to a file
func SaveConfig(filename string, config NodeConfig) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(filename, data, 0644)
}

// ValidateConfig validates the node configuration
func (n *Node) ValidateConfig() error {
    if n.NodeID == "" {
        return errors.New("node ID cannot be empty")
    }
    if n.Address == "" {
        return errors.New("address cannot be empty")
    }
    if n.Port == "" {
        return errors.New("port cannot be empty")
    }
    if n.Consensus == "" {
        return errors.New("consensus algorithm cannot be empty")
    }
    if n.Difficulty <= 0 {
        return errors.New("difficulty must be greater than 0")
    }
    if n.Stake < 0 {
        return errors.New("stake cannot be negative")
    }

    return nil
}

// PrintConfig prints the node configuration to the console
func (n *Node) PrintConfig() {
    config := NodeConfig{
        NodeID:           n.NodeID,
        Address:          n.Address,
        Port:             n.Port,
        Consensus:        n.Consensus,
        Difficulty:       n.Difficulty,
        Stake:            n.Stake,
        ValidatorAddress: n.ValidatorAddress,
    }

    data, _ := json.MarshalIndent(config, "", "  ")
    println(string(data))
}
