package syn3900

import (
    "encoding/json"
    "errors"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for storage operations, providing an abstraction over the actual storage mechanism.
type DataStore interface {
    SaveBenefitRegistry(registry *BenefitRegistry) error
    LoadBenefitRegistry() (*BenefitRegistry, error)
}

// FileStore implements the DataStore interface using the file system for persistent storage.
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

// SaveBenefitRegistry serializes the BenefitRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveBenefitRegistry(registry *BenefitRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "  ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadBenefitRegistry reads a file, deserializes its content into a BenefitRegistry, and returns it.
func (fs *FileStore) LoadBenefitRegistry() (*BenefitRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    if _, err := os.Stat(fs.FilePath); errors.Is(err, os.ErrNotExist) {
        // File does not exist, return a new registry
        return NewBenefitRegistry(), nil
    }

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        return nil, err
    }

    var registry BenefitRegistry
    if err = json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Initialize the map if it's nil (e.g., empty file or new registry)
    if registry.Benefits == nil {
        registry.Benefits = make(map[string]*BenefitToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
