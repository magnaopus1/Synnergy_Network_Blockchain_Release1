// Package backup provides the functionalities to manage geographically distributed backups.
package backup

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/synthron/synthron_blockchain/pkg/layer0/core/blockchain"
	"github.com/synthron/synthron_blockchain/pkg/utils"
)

// GeoBackupManager manages geographically distributed backups of blockchain data.
type GeoBackupManager struct {
	blockchain      *blockchain.Blockchain
	backupLocations []string
	backupInterval  time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// NewGeoBackupManager creates a new manager for geographically distributed backups.
func NewGeoBackupManager(bc *blockchain.Blockchain, locations []string, interval time.Duration) *GeoBackupManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &GeoBackupManager{
		blockchain:      bc,
		backupLocations: locations,
		backupInterval:  interval,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start initiates the periodic backup process.
func (gbm *GeoBackupManager) Start() {
	log.Println("Starting geographically distributed backup manager.")
	gbm.wg.Add(1)
	go gbm.scheduleBackups()
}

// scheduleBackups handles the timing of the backup operations.
func (gbm *GeoBackupManager) scheduleBackups() {
	defer gbm.wg.Done()
	ticker := time.NewTicker(gbm.backupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gbm.performBackup()
		case <-gbm.ctx.Done():
			log.Println("Stopping geographically distributed backup process.")
			return
		}
	}
}

// performBackup executes the backup process across all configured locations.
func (gbm *GeoBackupManager) performBackup() {
	log.Println("Performing geographically distributed backup.")
	data, err := gbm.blockchain.ExportData()
	if err != nil {
		log.Printf("Error exporting blockchain data: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, location := range gbm.backupLocations {
		wg.Add(1)
		go func(loc string) {
			defer wg.Done()
			if err := utils.StoreData(data, loc); err != nil {
				log.Printf("Failed to store data at location %s: %v", loc, err)
			} else {
				log.Printf("Backup successful at location %s", loc)
			}
		}(location)
	}
	wg.Wait()
}

// Stop halts the backup manager and waits for any ongoing operations to complete.
func (gbm *GeoBackupManager) Stop() {
	gbm.cancel()
	gbm.wg.Wait()
	log.Println("Geographically distributed backup manager stopped.")
}

// main function is used to demonstrate the usage of the GeoBackupManager.
func main() {
	// Placeholder for blockchain instance creation and initialization
	blockchainInstance := blockchain.NewBlockchain()

	// Define backup locations and interval
	backupLocations := []string{"North America", "Europe", "Asia"}
	backupManager := NewGeoBackupManager(blockchainInstance, backupLocations, 24*time.Hour)

	// Start the backup manager
	backupManager.Start()

	// Assume the system runs for some time and then needs to stop.
	time.Sleep(72 * time.Hour) // Simulate 3 days of runtime
	backupManager.Stop()
}
