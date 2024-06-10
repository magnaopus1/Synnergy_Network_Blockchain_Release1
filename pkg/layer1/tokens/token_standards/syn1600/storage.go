package syn1600

import (
    "encoding/json"
    "io/ioutil"
    "os"
    "sync"
)

// StorageManager defines the interface for storage operations.
type StorageManager interface {
    SaveToken(token *RoyaltyToken) error
    LoadToken(tokenID string) (*RoyaltyToken, error)
}

// FileStorageManager implements StorageManager using the local file system.
type FileStorageManager struct {
    BasePath string
    mutex    sync.Mutex
}

// NewFileStorageManager initializes a new file-based storage manager.
func NewFileStorageManager(basePath string) *FileStorageManager {
    return &FileStorageManager{
        BasePath: basePath,
    }
}

// SaveToken serializes the RoyaltyToken and saves it to a file.
func (fsm *FileStorageManager) SaveToken(token *RoyaltyToken) error {
    fsm.mutex.Lock()
    defer fsm.mutex.Unlock()

    tokenData, err := json.Marshal(token)
    if err != nil {
        return err
    }

    filePath := fsm.getTokenFilePath(token.ID)
    return ioutil.WriteFile(filePath, tokenData, 0644)
}

// LoadToken reads the file containing the serialized RoyaltyToken and deserializes it.
func (fsm *FileStorageManager) LoadToken(tokenID string) (*RoyaltyToken, error) {
    fsm.mutex.Lock()
    defer fsm.mutex.Unlock()

    filePath := fsm.getTokenFilePath(tokenID)
    tokenData, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    var token RoyaltyToken
    err = json.Unmarshal(tokenData, &token)
    if err != nil {
        return nil, err
    }

    return &token, nil
}

// getTokenFilePath generates the path to the file where the token is stored.
func (fsm *FileStorageManager) getTokenFilePath(tokenID string) string {
    return fsm.BasePath + "/" + tokenID + ".json"
}
