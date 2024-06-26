// Package backup provides the functionality to create and manage snapshots for data backup.
package backup

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/synthron/synthron_blockchain/pkg/layer0/core/blockchain"
)

// BackupSnapshotManager manages the creation and storage of blockchain snapshots for backup purposes.
type BackupSnapshotManager struct {
	blockchain     *blockchain.Blockchain
	snapshotDir    string
	snapshotPeriod time.Duration
	ticker         *time.Ticker
	stopChan       chan bool
	wg             sync.WaitGroup
}

// NewBackupSnapshotManager initializes a new backup snapshot manager.
func NewBackupSnapshotManager(blockchain *blockchain.Blockchain, snapshotDir string, snapshotPeriod time.Duration) *BackupSnapshotManager {
	return &BackupSnapshotManager{
		blockchain:     blockchain,
		snapshotDir:    snapshotDir,
		snapshotPeriod: snapshotPeriod,
		ticker:         time.NewTicker(snapshotPeriod),
		stopChan:       make(chan bool),
	}
}

// Start begins the periodic snapshot taking process.
func (bsm *BackupSnapshotManager) Start() {
	bsm.wg.Add(1)
	go func() {
		defer bsm.wg.Done()
		for {
			select {
			case <-bsm.ticker.C:
				bsm.takeSnapshot()
			case <-bsm.stopChan:
				log.Println("Stopping backup snapshot manager.")
				return
			}
		}
	}()
	log.Println("Backup snapshot manager started.")
}

// takeSnapshot captures the current state of the blockchain and stores it in the snapshot directory.
func (bsm *BackupSnapshotManager) takeSnapshot() {
	log.Println("Taking a new snapshot of the blockchain...")
	snapshot, err := bsm.blockchain.CreateSnapshot()
	if err != nil {
		log.Printf("Error taking blockchain snapshot: %v", err)
		return
	}

	snapshotData, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("Error marshaling snapshot data: %v", err)
		return
	}

	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(bsm.snapshotDir, timestamp+"-snapshot.json")
	err = ioutil.WriteFile(filename, snapshotData, 0644)
	if err != nil {
		log.Printf("Error writing snapshot to file: %v", err)
		return
	}

	log.Printf("Snapshot successfully saved to %s", filename)
}

// Stop halts the snapshot taking process and waits for the current snapshot operation to finish.
func (bsm *BackupSnapshotManager) Stop() {
	bsm.ticker.Stop()
	bsm.stopChan <- true
	bsm.wg.Wait()
	log.Println("Backup snapshot manager stopped successfully.")
}

// main function is used to demonstrate running the backup snapshot manager.
func main() {
	// Placeholder for blockchain instance creation and initialization
	blockchainInstance := blockchain.NewBlockchain()

	backupManager := NewBackupSnapshotManager(blockchainInstance, "/path/to/snapshot/dir", 24*time.Hour)
	backupManager.Start()

	// Assume the system runs for some time and then needs to stop.
	time.Sleep(48 * time.Hour)
	backupManager.Stop()
}
