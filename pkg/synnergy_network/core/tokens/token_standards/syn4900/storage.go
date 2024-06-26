package syn4900

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines the interface for storage operations used by the agricultural token registry.
type DataStore interface {
    SaveRegistry(registry *AgriculturalRegistry) error
    LoadRegistry() (*AgriculturalRegistry, error)
}

// FileDataStore implements DataStore using a local file system for storage.
type FileDataStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileDataStore creates a new instance of a FileDataStore.
func NewFileDataStore(filePath string) *FileDataStore {
    return &FileDataStore{FilePath: filePath}
}

// SaveRegistry serializes the AgriculturalRegistry to JSON and writes it to a file.
func (store *FileDataStore) SaveRegistry(registry *AgriculturalRegistry) error {
    store.mutex.Lock()
    defer store.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "    ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(store.FilePath, data, 0644)
}

// LoadRegistry reads a JSON file and deserializes it into an AgriculturalRegistry.
func (store *FileDataStore) LoadRegistry() (*AgriculturalRegistry, error) {
    store.mutex.Lock()
    defer store.mutex.Unlock()

    if _, err := os.Stat(store.FilePath); os.IsNotExist(err) {
        // If the file does not exist, initialize a new registry
        return NewAgriculturalRegistry(), nil
    }

    data, err := ioutil.ReadFile(store.FilePath)
    if err != nil {
        return nil, err
    }

    var registry AgriculturalRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure that the Tokens map is initialized if it's nil due to being empty
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*AgriculturalToken)
    }

    return &registry, nil
}

// Ensure that FileDataStore implements the DataStore interface
var _ DataStore = &FileDataStore{}
