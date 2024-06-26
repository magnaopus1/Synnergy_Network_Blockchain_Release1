package syn3700

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for storage operations, ensuring flexibility and scalability.
type DataStore interface {
    SaveIndexRegistry(registry *IndexRegistry) error
    LoadIndexRegistry() (*IndexRegistry, error)
}

// FileStore implements the DataStore interface using the file system for persistence.
type FileStore struct {
    FilePath string
    mutex    sync.Mutex
}

// NewFileStore initializes a new FileStore with the specified file path.
func NewFileStore(filePath string) *FileStore {
    return &FileStore{
        FilePath: filePath,
    }
}

// SaveIndexRegistry serializes the IndexRegistry to JSON and writes it to a file.
func (fs *FileStore) SaveIndexRegistry(registry *IndexRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadIndexRegistry reads the file, deserializes it into an IndexRegistry, and returns it.
func (fs *FileStore) LoadIndexRegistry() (*IndexRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        if os.IsNotExist(err) {
            // Return a new IndexRegistry if the file does not exist.
            return NewIndexRegistry(), nil
        }
        return nil, err
    }

    var registry IndexRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure all maps are properly initialized.
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*IndexToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
