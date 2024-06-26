package syn2100

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
)

// Storage represents the interface for persisting and retrieving ledger data.
type Storage interface {
	SaveLedger(ledger *SupplyChainLedger) error
	LoadLedger() (*SupplyChainLedger, error)
}

// FileStorage implements the Storage interface using a file system for data persistence.
type FileStorage struct {
	Path string
	mu   sync.Mutex
}

// NewFileStorage creates a new instance of FileStorage.
func NewFileStorage(path string) *FileStorage {
	return &FileStorage{
		Path: path,
	}
}

// SaveLedger serializes the SupplyChainLedger to JSON and saves it to a file.
func (fs *FileStorage) SaveLedger(ledger *SupplyChainLedger) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.Marshal(ledger)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fs.Path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadLedger reads the ledger from a file and deserializes it from JSON.
func (fs *FileStorage) LoadLedger() (*SupplyChainLedger, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := ioutil.ReadFile(fs.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return an empty ledger if the file does not exist
			return NewSupplyChainLedger(), nil
		}
		return nil, err
	}

	var ledger SupplyChainLedger
	err = json.Unmarshal(data, &ledger)
	if err != nil {
		return nil, err
	}

	return &ledger, nil
}

// Ensure data integrity and handle potential concurrency issues by using a mutex.
// This approach ensures that operations on the file system are thread-safe, preventing data corruption.

