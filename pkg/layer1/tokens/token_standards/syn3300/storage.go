package syn3300

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore is an interface for the storage backend, allowing for easy swapping and testing.
type DataStore interface {
    SaveETFRegistry(registry *ETFRegistry) error
    LoadETFRegistry() (*ETFRegistry, error)
}

// FileStore implements DataStore using the filesystem for storage.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore creates a new FileStore.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveETFRegistry serializes the ETFRegistry to JSON and saves it to a file.
func (fs *FileStore) SaveETFRegistry(registry *ETFRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.Marshal(registry)
    if err != nil {
        return err
    }

    // Write data to the file with read and write permissions set.
    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadETFRegistry loads and deserializes the ETFRegistry from a file.
func (fs *FileStore) LoadETFRegistry() (*ETFRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // Return an empty registry if the file does not exist.
            return NewETFRegistry(nil), nil
        }
        return nil, err
    }

    var registry ETFRegistry
    err = json.Unmarshal(data, &registry)
    if err != nil {
        return nil, err
    }

    // Re-initialize any runtime structs or interfaces that are not serialized.
    registry.ETFs = make(map[string]*ETF)
    registry.Tokens = make(map[string]*ETFShareToken)

    // Assume dataFetcher needs to be set externally after loading.
    return &registry, nil
}

// Ensure implementations fulfill the interface.
var _ DataStore = &FileStore{}
