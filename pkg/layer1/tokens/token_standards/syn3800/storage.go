package syn3800

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for the storage operations required for grant tokens.
type DataStore interface {
    SaveGrantRegistry(registry *GrantRegistry) error
    LoadGrantRegistry() (*GrantRegistry, error)
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

// SaveGrantRegistry serializes the GrantRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveGrantRegistry(registry *GrantRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadGrantRegistry reads a file, deserializes its content into a GrantRegistry, and returns it.
func (fs *FileStore) LoadGrantRegistry() (*GrantRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // If the file does not exist, initialize a new GrantRegistry
            return NewGrantRegistry(), nil
        }
        return nil, err
    }

    var registry GrantRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure the Grants map is properly initialized
    if registry.Grants == nil {
        registry.Grants = make(map[string]*GrantToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
