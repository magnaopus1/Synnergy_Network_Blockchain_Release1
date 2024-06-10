package syn4300

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for storage operations required by the energy registry.
type DataStore interface {
    SaveEnergyRegistry(registry *EnergyRegistry) error
    LoadEnergyRegistry() (*EnergyRegistry, error)
}

// FileStore implements the DataStore interface using the file system for persistent storage.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore creates a new instance of FileStore with a specified file path.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveEnergyRegistry serializes the EnergyRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveEnergyRegistry(registry *EnergyRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadEnergyRegistry reads a file, deserializes its content into an EnergyRegistry, and returns it.
func (fs *FileStore) LoadEnergyRegistry() (*EnergyRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    if _, err := os.Stat(fs.FilePath); os.IsNotExist(err) {
        // If the file does not exist, return a new initialized registry
        return NewEnergyRegistry(), nil
    }

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        return nil, err
    }

    var registry EnergyRegistry
    if err = json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure the Tokens map is properly initialized
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*EnergyToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
