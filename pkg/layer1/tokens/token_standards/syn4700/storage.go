package syn4700

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// DataStore defines an interface for the storage operations required by the legal registry.
type DataStore interface {
    SaveLegalRegistry(registry *LegalRegistry) error
    LoadLegalRegistry() (*LegalRegistry, error)
}

// FileStore implements the DataStore interface using a file-based storage mechanism.
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

// SaveLegalRegistry serializes the LegalRegistry into JSON and writes it to a file.
func (fs *FileStore) SaveLegalRegistry(registry *LegalRegistry) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    data, err := json.MarshalIndent(registry, "", "    ")
    if err != nil {
        return err
    }

    return ioutil.WriteFile(fs.FilePath, data, 0644)
}

// LoadLegalRegistry reads a file, deserializes its content into a LegalRegistry, and returns it.
func (fs *FileStore) LoadLegalRegistry() (*LegalRegistry, error) {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    if _, err := os.Stat(fs.FilePath); os.IsNotExist(err) {
        // If the file does not exist, return a new initialized registry
        return NewLegalRegistry(), nil
    }

    data, err := ioutil.ReadFile(fs.FilePath)
    if err != nil {
        return nil, err
    }

    var registry LegalRegistry
    if err := json.Unmarshal(data, &registry); err != nil {
        return nil, err
    }

    // Ensure the Tokens map is properly initialized if nil
    if registry.Tokens == nil {
        registry.Tokens = make(map[string]*LegalToken)
    }

    return &registry, nil
}

// Ensure that FileStore implements the DataStore interface.
var _ DataStore = &FileStore{}
