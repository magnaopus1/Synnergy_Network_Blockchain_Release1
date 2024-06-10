// Package backup provides functionalities for handling incremental backups of blockchain data.
package backup

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/synthron/synthron_blockchain/pkg/layer0/core/blockchain"
	"github.com/synthron/synthron_blockchain/pkg/utils"
)

// IncrementalBackupManager handles the incremental backup process.
type IncrementalBackupManager struct {
	blockchain   *blockchain.Blockchain
	backupDir    string
	lastSnapshot time.Time
	mu           sync.Mutex
}

// NewIncrementalBackupManager creates a new incremental backup manager.
func NewIncrementalBackupManager(bc *blockchain.Blockchain, dir string) *IncrementalBackupManager {
	return &IncrementalBackupManager{
		blockchain: bc,
		backupDir:  dir,
	}
}

// Start initiates the backup process at specified intervals.
func (ibm *IncrementalBackupManager) Start(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := ibm.performBackup(); err != nil {
			fmt.Printf("Error performing backup: %v\n", err)
			continue
		}
	}
}

// performBackup captures and saves the incremental changes since the last backup.
func (ibm *IncrementalBackupManager) performBackup() error {
	ibm.mu.Lock()
	defer ibm.mu.Unlock()

	currentState, err := ibm.blockchain.ExportData()
	if err != nil {
		return fmt.Errorf("failed to export blockchain data: %w", err)
	}

	backupFilePath := filepath.Join(ibm.backupDir, fmt.Sprintf("backup-%d.gob", time.Now().Unix()))
	file, err := os.Create(backupFilePath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(currentState); err != nil {
		return fmt.Errorf("failed to encode data: %w", err)
	}

	// Update the last snapshot time after a successful backup
	ibm.lastSnapshot = time.Now()
	fmt.Printf("Backup successful at %s\n", backupFilePath)
	return nil
}

// Restore loads the most recent backup data into the blockchain.
func (ibm *IncrementalBackupManager) Restore() error {
	files, err := filepath.Glob(filepath.Join(ibm.backupDir, "backup-*.gob"))
	if err != nil {
		return fmt.Errorf("failed to list backup files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no backups found")
	}

	latestBackup := files[len(files)-1]
	file, err := os.Open(latestBackup)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	var state blockchain.Data
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}

	if err := ibm.blockchain.ImportData(state); err != nil {
		return fmt.Errorf("failed to import data: %w", err)
	}

	fmt.Printf("Restored blockchain from backup: %s\n", latestBackup)
	return nil
}

// main demonstrates how to use the IncrementalBackupManager.
func main() {
	bc := blockchain.NewBlockchain() // Placeholder for actual blockchain initialization
	manager := NewIncrementalBackupManager(bc, "/path/to/backup/dir")

	// Start backup every 24 hours
	go manager.Start(24 * time.Hour)

	// Example to stop and restore from the latest backup if needed
	time.Sleep(72 * time.Hour) // simulate time passage
	if err := manager.Restore(); err != nil {
		fmt.Printf("Failed to restore from backup: %v\n", err)
	}
}
