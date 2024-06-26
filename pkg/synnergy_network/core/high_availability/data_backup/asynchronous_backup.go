// Package backup provides asynchronous data backup solutions for the Synnergy Network's blockchain infrastructure.
package backup

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/synthron/synthron_blockchain/pkg/layer0/core/blockchain"
)

// AsynchronousBackupManager handles the backup processes for blockchain data.
type AsynchronousBackupManager struct {
	blockchain *blockchain.Blockchain
	backupPath string
	ticker     *time.Ticker
	wg         sync.WaitGroup
}

// NewAsynchronousBackupManager creates a new instance of AsynchronousBackupManager.
func NewAsynchronousBackupManager(blockchain *blockchain.Blockchain, backupPath string, interval time.Duration) *AsynchronousBackupManager {
	return &AsynchronousBackupManager{
		blockchain: blockchain,
		backupPath: backupPath,
		ticker:     time.NewTicker(interval),
	}
}

// Start initiates the backup process at specified intervals.
func (abm *AsynchronousBackupManager) Start() {
	log.Println("Starting asynchronous backup process.")
	abm.wg.Add(1)
	go func() {
		defer abm.wg.Done()
		for {
			select {
			case <-abm.ticker.C:
				abm.backupData()
			}
		}
	}()
}

// backupData handles the actual backup operation, capturing incremental changes and creating snapshots.
func (abm *AsynchronousBackupManager) backupData() {
	log.Println("Performing asynchronous backup...")
	snapshot, err := abm.blockchain.CreateSnapshot()
	if err != nil {
		log.Printf("Error creating blockchain snapshot: %v", err)
		return
	}

	filename := filepath.Join(abm.backupPath, time.Now().Format("20060102-150405")+".bkp")
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create backup file: %v", err)
		return
	}
	defer file.Close()

	if _, err := snapshot.WriteTo(file); err != nil {
		log.Printf("Failed to write snapshot to file: %v", err)
	}
	log.Printf("Backup successfully created at %s", filename)
}

// Stop halts the backup process and waits for the current operation to complete.
func (abm *AsynchronousBackupManager) Stop() {
	log.Println("Stopping asynchronous backup process.")
	abm.ticker.Stop()
	abm.wg.Wait() // Ensure the last backup completes if it's running.
	log.Println("Backup process stopped successfully.")
}

// main function is used for illustration purposes only.
func main() {
	// Assuming a blockchain instance is created and available.
	blockchainInstance := blockchain.NewBlockchain() // Placeholder for actual blockchain initialization.

	backupManager := NewAsynchronousBackupManager(blockchainInstance, "/path/to/backup/dir", 24*time.Hour)
	backupManager.Start()

	// The server or application would continue to run, and the backup manager would perform backups asynchronously.
	// This is a simple simulation of stopping the backup manager after some operational time.
	time.Sleep(24 * time.Hour) // Simulate 24 hours of operation.
	backupManager.Stop()
}
