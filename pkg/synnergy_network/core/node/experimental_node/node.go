package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"encoding/json"
	"sync"
	"github.com/synthron_blockchain_final/pkg/layer0/node/common"
	"github.com/synthron_blockchain_final/pkg/layer0/node/security"
	"github.com/synthron_blockchain_final/pkg/layer0/node/storage"
	"github.com/synthron_blockchain_final/pkg/layer0/node/testing"
)

type ExperimentalNode struct {
	config    *NodeConfig
	blockchain *Blockchain
	storage    *storage.Storage
	security   *security.Security
	logger     *log.Logger
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

type NodeConfig struct {
	NodeID             string `json:"node_id"`
	TestMode           bool   `json:"test_mode"`
	ConsensusAlgorithm string `json:"consensus_algorithm"`
	NetworkID          string `json:"network_id"`
	LogLevel           string `json:"log_level"`
	StoragePath        string `json:"storage_path"`
}

type Blockchain struct {
	// Blockchain-specific fields and methods
}

func NewExperimentalNode(configPath string) (*ExperimentalNode, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	storage, err := storage.NewStorage(config.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %v", err)
	}

	security, err := security.NewSecurity()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security: %v", err)
	}

	logger := log.New(os.Stdout, "ExperimentalNode: ", log.LstdFlags)
	if config.LogLevel == "DEBUG" {
		logger.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	node := &ExperimentalNode{
		config:    config,
		blockchain: &Blockchain{},
		storage:    storage,
		security:   security,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}

	return node, nil
}

func LoadConfig(configPath string) (*NodeConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config NodeConfig
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (node *ExperimentalNode) Start() {
	node.logger.Println("Starting Experimental Node...")
	node.wg.Add(1)
	go node.run()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	node.Stop()
}

func (node *ExperimentalNode) run() {
	defer node.wg.Done()
	node.logger.Println("Experimental Node is running...")

	for {
		select {
		case <-node.stopCh:
			node.logger.Println("Stopping Experimental Node...")
			return
		default:
			// Node operations go here, such as processing transactions, validating blocks, etc.
			node.processTransactions()
			node.validateBlocks()
			time.Sleep(1 * time.Second) // Simulate work
		}
	}
}

func (node *ExperimentalNode) Stop() {
	close(node.stopCh)
	node.wg.Wait()
	node.logger.Println("Experimental Node stopped.")
}

func (node *ExperimentalNode) processTransactions() {
	// Implement transaction processing logic here
	node.logger.Println("Processing transactions...")
}

func (node *ExperimentalNode) validateBlocks() {
	// Implement block validation logic here
	node.logger.Println("Validating blocks...")
}

func main() {
	configPath := "config.toml"
	node, err := NewExperimentalNode(configPath)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}

	node.Start()
}
