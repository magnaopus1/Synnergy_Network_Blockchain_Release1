package syn3600

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore is an interface that defines methods for saving and loading a futures registry.
type DataStore interface {
    SaveFuturesRegistry(registry *FuturesRegistry) error
    LoadFuturesRegistry() (*FuturesRegistry, error)
}

// FileStore implements the DataStore interface using a file system.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore creates a new instance of FileStore.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveFuturesRegistry serializes the FuturesRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveFuturesRegistry(registry *FuturesRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadFuturesRegistry reads a file, deserializes it into a FuturesRegistry object.
func (fs *FileStore) LoadFuturesRegistry() (*FuturesRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // If the file doesn't exist, initialize a new FuturesRegistry
            return NewFuturesRegistry(), nil
        }
        return nil, err
    }

    var registry FuturesRegistry
    if err = json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure all maps are initialized properly if they're nil
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*FutureToken)
    }

    return &registry, nil
}

// Ensure FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
