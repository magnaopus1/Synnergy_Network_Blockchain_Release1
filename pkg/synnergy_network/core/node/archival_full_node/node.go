package validator_node

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/synthron/blockchain/pkg/consensus"
    "github.com/synthron/blockchain/pkg/crypto"
    "github.com/synthron/blockchain/pkg/network"
    "github.com/synthron/blockchain/pkg/storage"
    "github.com/synthron/blockchain/pkg/transaction"
    "github.com/synthron/blockchain/pkg/utilities"
)

// ValidatorNode represents a node that participates in the validation of transactions and blocks.
type ValidatorNode struct {
    ID           string
    Stake        uint64
    NodeConfig   *NodeConfig
    Consensus    *consensus.Consensus
    Network      *network.Network
    TransactionPool *transaction.Pool
    Storage      *storage.Storage
    Mutex        sync.Mutex
    running      bool
}

// NodeConfig holds configuration parameters for the validator node.
type NodeConfig struct {
    TLSCertFile        string `json:"tls_cert_file"`
    TLSKeyFile         string `json:"tls_key_file"`
    TLSCAFile          string `json:"tls_ca_file"`
    StakingKey         string `json:"staking_key"`
    MinimumStake       uint64 `json:"minimum_stake"`
    NetworkParameters  *network.Parameters `json:"network_parameters"`
}

// NewValidatorNode creates a new Validator Node with the given configuration.
func NewValidatorNode(config *NodeConfig) (*ValidatorNode, error) {
    if config.MinimumStake == 0 {
        return nil, fmt.Errorf("minimum stake cannot be zero")
    }

    // Initialize network, consensus, transaction pool, and storage
    net := network.NewNetwork(config.NetworkParameters)
    cons := consensus.NewConsensus()
    pool := transaction.NewPool()
    store := storage.NewStorage()

    node := &ValidatorNode{
        ID:               utilities.GenerateNodeID(),
        Stake:            0,
        NodeConfig:       config,
        Consensus:        cons,
        Network:          net,
        TransactionPool:  pool,
        Storage:          store,
        running:          false,
    }

    return node, nil
}

// Start begins the operation of the validator node.
func (node *ValidatorNode) Start() error {
    node.Mutex.Lock()
    defer node.Mutex.Unlock()

    if node.running {
        return fmt.Errorf("node is already running")
    }

    tlsConfig, err := loadTLSConfig(node.NodeConfig.TLSCertFile, node.NodeConfig.TLSKeyFile, node.NodeConfig.TLSCAFile)
    if err != nil {
        return fmt.Errorf("failed to load TLS configuration: %v", err)
    }

    // Start network communication
    go node.Network.Start(tlsConfig)

    // Start consensus process
    go node.Consensus.Start(node)

    node.running = true
    return nil
}

// Stop halts the operation of the validator node.
func (node *ValidatorNode) Stop() error {
    node.Mutex.Lock()
    defer node.Mutex.Unlock()

    if !node.running {
        return fmt.Errorf("node is not running")
    }

    node.Network.Stop()
    node.Consensus.Stop()

    node.running = false
    return nil
}

// ValidateTransaction validates a transaction.
func (node *ValidatorNode) ValidateTransaction(tx *transaction.Transaction) error {
    if err := tx.Verify(); err != nil {
        return fmt.Errorf("transaction verification failed: %v", err)
    }

    if !node.Consensus.ValidateTransaction(tx) {
        return fmt.Errorf("transaction consensus validation failed")
    }

    return nil
}

// ProposeBlock proposes a new block to the network.
func (node *ValidatorNode) ProposeBlock() (*consensus.Block, error) {
    node.Mutex.Lock()
    defer node.Mutex.Unlock()

    if !node.running {
        return nil, fmt.Errorf("node is not running")
    }

    transactions := node.TransactionPool.GetPendingTransactions()
    newBlock, err := node.Consensus.ProposeBlock(node, transactions)
    if err != nil {
        return nil, fmt.Errorf("failed to propose block: %v", err)
    }

    if err := node.Network.BroadcastBlock(newBlock); err != nil {
        return nil, fmt.Errorf("failed to broadcast block: %v", err)
    }

    return newBlock, nil
}

// VoteOnBlock casts a vote on a proposed block.
func (node *ValidatorNode) VoteOnBlock(block *consensus.Block) error {
    vote, err := node.Consensus.VoteOnBlock(node, block)
    if err != nil {
        return fmt.Errorf("failed to vote on block: %v", err)
    }

    if err := node.Network.BroadcastVote(vote); err != nil {
        return fmt.Errorf("failed to broadcast vote: %v", err)
    }

    return nil
}

// PerformHealthCheck performs a health check on the validator node.
func (node *ValidatorNode) PerformHealthCheck() error {
    // Implement health check logic, such as checking network connectivity, memory usage, etc.
    return nil
}

// loadTLSConfig loads the TLS configuration for the validator node.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load TLS key pair: %v", err)
    }

    caCert, err := ioutil.ReadFile(caFile)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA certificate: %v", err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    }, nil
}
