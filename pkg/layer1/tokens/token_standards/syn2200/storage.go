package syn2200

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
)

// Storage is the interface for storage operations on Payment Tokens.
type Storage interface {
	SaveToken(token *PaymentToken) error
	LoadToken(tokenID string) (*PaymentToken, error)
	SaveAll() error
	LoadAll() error
}

// FileStorage implements the Storage interface using a file system for persistence.
type FileStorage struct {
	Path   string                  // File path for storing token data
	Tokens map[string]*PaymentToken // In-memory cache of tokens
	mu     sync.RWMutex            // Mutex to handle concurrency within the file storage
}

// NewFileStorage creates a new FileStorage.
func NewFileStorage(path string) *FileStorage {
	fs := &FileStorage{
		Path:   path,
		Tokens: make(map[string]*PaymentToken),
	}
	fs.LoadAll() // Load existing tokens from file
	return fs
}

// SaveToken saves a single payment token into the storage.
func (fs *FileStorage) SaveToken(token *PaymentToken) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.Tokens[token.TokenID] = token
	return fs.saveToFile()
}

// LoadToken loads a single payment token from the storage.
func (fs *FileStorage) LoadToken(tokenID string) (*PaymentToken, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	token, exists := fs.Tokens[tokenID]
	if !exists {
		return nil, os.ErrNotExist
	}
	return token, nil
}

// SaveAll saves all tokens to the file system.
func (fs *FileStorage) SaveAll() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.saveToFile()
}

// LoadAll loads all tokens from the file system.
func (fs *FileStorage) LoadAll() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := ioutil.ReadFile(fs.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No data to load
		}
		return err
	}

	return json.Unmarshal(data, &fs.Tokens)
}

// saveToFile writes the in-memory tokens to the file system.
func (fs *FileStorage) saveToFile() error {
	data, err := json.Marshal(fs.Tokens)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fs.Path, data, 0644)
}


