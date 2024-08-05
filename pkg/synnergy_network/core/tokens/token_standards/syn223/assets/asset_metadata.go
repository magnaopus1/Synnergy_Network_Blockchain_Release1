package assets

import (
    "encoding/json"
    "errors"
    "sync"
)

// TokenMetadata represents the metadata of a SYN223 token.
type TokenMetadata struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Symbol      string `json:"symbol"`
    TotalSupply uint64 `json:"total_supply"`
    Decimals    uint8  `json:"decimals"`
}

// MetadataStore represents a storage for token metadata.
type MetadataStore struct {
    mu        sync.RWMutex
    store     map[string]TokenMetadata
}

// NewMetadataStore initializes a new metadata store.
func NewMetadataStore() *MetadataStore {
    return &MetadataStore{
        store: make(map[string]TokenMetadata),
    }
}

// AddMetadata adds new token metadata to the store.
func (ms *MetadataStore) AddMetadata(metadata TokenMetadata) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    if _, exists := ms.store[metadata.ID]; exists {
        return errors.New("metadata already exists for this token ID")
    }

    ms.store[metadata.ID] = metadata
    return nil
}

// UpdateMetadata updates existing token metadata in the store.
func (ms *MetadataStore) UpdateMetadata(metadata TokenMetadata) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    if _, exists := ms.store[metadata.ID]; !exists {
        return errors.New("metadata does not exist for this token ID")
    }

    ms.store[metadata.ID] = metadata
    return nil
}

// GetMetadata retrieves token metadata by ID.
func (ms *MetadataStore) GetMetadata(id string) (TokenMetadata, error) {
    ms.mu.RLock()
    defer ms.mu.RUnlock()

    metadata, exists := ms.store[id]
    if !exists {
        return TokenMetadata{}, errors.New("metadata not found for this token ID")
    }

    return metadata, nil
}

// DeleteMetadata removes token metadata from the store.
func (ms *MetadataStore) DeleteMetadata(id string) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    if _, exists := ms.store[id]; !exists {
        return errors.New("metadata not found for this token ID")
    }

    delete(ms.store, id)
    return nil
}

// ExportMetadata exports all token metadata to JSON format.
func (ms *MetadataStore) ExportMetadata() (string, error) {
    ms.mu.RLock()
    defer ms.mu.RUnlock()

    data, err := json.Marshal(ms.store)
    if err != nil {
        return "", err
    }

    return string(data), nil
}

// ImportMetadata imports token metadata from JSON format.
func (ms *MetadataStore) ImportMetadata(jsonData string) error {
    ms.mu.Lock()
    defer ms.mu.Unlock()

    var importedData map[string]TokenMetadata
    if err := json.Unmarshal([]byte(jsonData), &importedData); err != nil {
        return err
    }

    for id, metadata := range importedData {
        ms.store[id] = metadata
    }

    return nil
}
