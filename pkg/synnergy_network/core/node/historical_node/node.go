package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/pelletier/go-toml"
)

// Config struct holds the configuration for the Historical Node
type Config struct {
	DataDir   string `toml:"data_dir"`
	LogDir    string `toml:"log_dir"`
	BackupDir string `toml:"backup_dir"`
}

// HistoricalNode struct defines the node's properties
type HistoricalNode struct {
	config      Config
	db          *badger.DB
	dataDir     string
	logDir      string
	backupDir   string
	mu          sync.Mutex
	shutdownCh  chan struct{}
	isShutDown  bool
	isShutDownW sync.WaitGroup
}

// NewHistoricalNode initializes and returns a new HistoricalNode
func NewHistoricalNode(configPath string) (*HistoricalNode, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	opts := badger.DefaultOptions(config.DataDir)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	return &HistoricalNode{
		config:     config,
		db:         db,
		dataDir:    config.DataDir,
		logDir:     config.LogDir,
		backupDir:  config.BackupDir,
		shutdownCh: make(chan struct{}),
	}, nil
}

// loadConfig loads the configuration from a given path
func loadConfig(configPath string) (Config, error) {
	config := Config{}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}
	if err := toml.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}

// Start begins the operation of the HistoricalNode
func (node *HistoricalNode) Start() {
	log.Println("Starting Historical Node...")
	node.isShutDownW.Add(1)
	go node.run()
}

// run contains the main operational logic for the HistoricalNode
func (node *HistoricalNode) run() {
	defer node.isShutDownW.Done()

	for {
		select {
		case <-node.shutdownCh:
			log.Println("Historical Node shutting down...")
			return
		default:
			node.performRoutineChecks()
			time.Sleep(5 * time.Minute) // Adjust the frequency as needed
		}
	}
}

// performRoutineChecks conducts regular integrity checks and maintenance
func (node *HistoricalNode) performRoutineChecks() {
	log.Println("Performing routine checks...")
	node.checkDataIntegrity()
	node.performBackups()
}

// checkDataIntegrity verifies the integrity of the stored data
func (node *HistoricalNode) checkDataIntegrity() {
	err := node.db.View(func(txn *badger.Txn) error {
		// Implement your integrity check logic here
		return nil
	})

	if err != nil {
		log.Printf("Error during data integrity check: %v\n", err)
	}
}

// performBackups handles the creation of data backups
func (node *HistoricalNode) performBackups() {
	backupPath := filepath.Join(node.backupDir, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(backupPath, os.ModePerm); err != nil {
		log.Printf("Error creating backup directory: %v\n", err)
		return
	}

	_, err := node.db.Backup(nil, 0)
	if err != nil {
		log.Printf("Error during backup: %v\n", err)
	}
}

// Stop gracefully shuts down the HistoricalNode
func (node *HistoricalNode) Stop() {
	node.mu.Lock()
	defer node.mu.Unlock()

	if node.isShutDown {
		return
	}

	node.isShutDown = true
	close(node.shutdownCh)
	node.isShutDownW.Wait()

	log.Println("Closing database...")
	if err := node.db.Close(); err != nil {
		log.Printf("Error closing database: %v\n", err)
	}
}

// ValidateTransaction ensures that a transaction is valid and untampered
func (node *HistoricalNode) ValidateTransaction(data []byte, hash string) bool {
	calculatedHash := sha256.Sum256(data)
	return hash == hex.EncodeToString(calculatedHash[:])
}

func main() {
	configPath := "path/to/config.toml" // Update with the actual path to the config file
	node, err := NewHistoricalNode(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize Historical Node: %v\n", err)
	}

	node.Start()

	// Simulate running the node
	time.Sleep(1 * time.Hour)

	node.Stop()
}
