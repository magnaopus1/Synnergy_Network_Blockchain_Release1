package syn3500

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore is an interface for the storage backend, allowing flexibility and the possibility to switch between different storage mechanisms.
type DataStore interface {
    SaveCurrencyRegistry(registry *CurrencyRegistry) error
    LoadCurrencyRegistry() (*CurrencyRegistry, error)
}

// FileStore implements the DataStore interface using file system storage.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore creates a new FileStore instance.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveCurrencyRegistry serializes the CurrencyRegistry to JSON and saves it to a file.
func (fs *FileStore) SaveCurrencyRegistry(registry *CurrencyRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadCurrencyRegistry deserializes the JSON data from a file into a CurrencyRegistry.
func (fs *FileStore) LoadCurrencyRegistry() (*CurrencyRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // Return a new registry if the file does not exist
            return NewCurrencyRegistry(), nil
        }
        return nil, err
    }

    var registry CurrencyRegistry
    if err = json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Reconstruct map if necessary
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*CurrencyToken)
    }

    return &registry, nil
}

// Ensure that FileStore fulfills the DataStore interface.
var _ DataStore = &FileStore{}
