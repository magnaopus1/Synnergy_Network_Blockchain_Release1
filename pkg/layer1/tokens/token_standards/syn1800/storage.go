package syn1800

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
)

// Storage is the interface for storage operations.
type Storage interface {
	SaveLedger(ledger *SYN1800Ledger) error
	LoadLedger() (*SYN1800Ledger, error)
}

// FileStorage implements the Storage interface using a file system for persistence.
type FileStorage struct {
	Path string
	lock sync.Mutex
}

// NewFileStorage creates a new instance of FileStorage.
func NewFileStorage(filePath string) *FileStorage {
	return &FileStorage{
		Path: filePath,
	}
}

// SaveLedger saves the current state of the SYN1800Ledger to a file.
func (fs *FileStorage) SaveLedger(ledger *SYN1800Ledger) error {
	fs.lock.Lock()
	defer fs.lock.Unlock()

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

// LoadLedger loads the SYN1800Ledger from a file.
func (fs *FileStorage) LoadLedger() (*SYN1800Ledger, error) {
	fs.lock.Lock()
	defer fs.lock.Unlock()

	data, err := ioutil.ReadFile(fs.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// If the file does not exist, return an empty ledger
			return NewSYN1800Ledger(), nil
		}
		return nil, err
	}

	var ledger SYN1800Ledger
	err = json.Unmarshal(data, &ledger)
	if err != nil {
		return nil, err
	}

	return &ledger, nil
}
