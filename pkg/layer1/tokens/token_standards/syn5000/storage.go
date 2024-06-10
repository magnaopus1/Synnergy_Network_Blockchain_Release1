package syn5000

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines the interface for storage operations, allowing for potential future expansion to different storage backends.
type DataStore interface {
    SaveRegistry(registry *GamblingRegistry) error
    LoadRegistry() (*GamblingRegistry, error)
}

// FileDataStore implements DataStore using the local file system, suitable for demonstration purposes or small-scale deployments.
type FileDataStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileDataStore initializes a new file-based data store.
func NewFileDataStore(filePath string) *FileDataStore {
    return &FileDataStore{
        FilePath: filePath,
    }
}

// SaveRegistry serializes the GamblingRegistry into JSON and writes it to a file.
func (store *FileDataStore) SaveRegistry(registry *GamblingRegistry) error {
    store.mutex.Lock()
    defer store.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "    ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(store.FilePath, data, 0644)
}

// LoadRegistry reads the JSON file and deserializes it into a GamblingRegistry.
func (store *FileDataStore) LoadRegistry() (*GamblingRegistry, error) {
    store.mutex.Lock()
    defer store.mutex.Unlock()

    data, err := ioutil.ReadFile(store.FilePath)
    if os.IsNotExist(err) {
        // File does not exist, so return a new registry
        return NewGamblingRegistry(), nil
    } else if err != nil {
        return nil, err
    }

    var registry GamblingRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure that the Tokens map is properly initialized if it's nil
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*GamblingToken)
    }

    return &registry, nil
}

// Ensure FileDataStore implements DataStore
var _ DataStore = &FileDataStore{}
