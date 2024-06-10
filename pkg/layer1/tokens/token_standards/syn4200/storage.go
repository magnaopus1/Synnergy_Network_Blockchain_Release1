package syn4200

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for the storage operations required by the charity registry.
type DataStore interface {
    SaveCharityRegistry(registry *CharityRegistry) error
    LoadCharityRegistry() (*CharityRegistry, error)
}

// FileStore implements the DataStore interface using a file-based storage mechanism.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore creates a new instance of FileStore with the specified file path.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveCharityRegistry serializes the CharityRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveCharityRegistry(registry *CharityRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadCharityRegistry reads a file, deserializes its content into a CharityRegistry, and returns it.
func (fs *FileStore) LoadCharityRegistry() (*CharityRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    if _, err := os.Stat(fs.FilePath); os.IsNotExist(err) {
        // If the file does not exist, return a new initialized registry
        return NewCharityRegistry(), nil
    }

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        return nil, err
    }

    var registry CharityRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure the Tokens map is properly initialized
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*CharityToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}

