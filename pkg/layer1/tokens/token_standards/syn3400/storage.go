package syn3400

import (
    "encoding/json"
    "io/ioutil"
    "sync"
    "os"
)

// DataStore is an interface for the storage backend, which allows swapping between different storage solutions.
type DataStore interface {
    SaveForexRegistry(registry *ForexRegistry) error
    LoadForexRegistry() (*ForexRegistry, error)
}

// FileStore implements the DataStore interface using the filesystem.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore initializes a new FileStore with a specified file path.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveForexRegistry serializes the ForexRegistry to JSON and writes it to a file.
func (fs *FileStore) SaveForexRegistry(registry *ForexRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "    ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadForexRegistry loads and deserializes the ForexRegistry from a file.
func (fs *FileStore) LoadForexRegistry() (*ForexRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // If the file does not exist, return a new registry instance.
            return NewForexRegistry(), nil
        }
        return nil, err
    }

    var registry ForexRegistry
    err = json.Unmarshal(data, &registry)
    if err != nil {
        return nil, err
    }

    // Re-initialize maps to ensure they are not nil.
    registry.ForexPairs = make(map[string]*ForexPair)
    registry.Tokens = make(map[string]*ForexToken)

    return &registry, nil
}

// Ensure that FileStore fulfills the DataStore interface.
var _ DataStore = &FileStore{}
