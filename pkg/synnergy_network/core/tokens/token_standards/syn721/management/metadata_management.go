package management

import (
	"fmt"
	"sync"
	"time"
)

// Metadata represents the metadata of a SYN721 token
type Metadata struct {
	Name        string
	Description string
	Image       string
	Attributes  map[string]string
}

// MetadataChange represents a change in the metadata of a SYN721 token
type MetadataChange struct {
	Timestamp   time.Time
	OldMetadata Metadata
	NewMetadata Metadata
}

// MetadataManager manages the metadata of SYN721 tokens
type MetadataManager struct {
	metadata           map[string]Metadata
	metadataHistories  map[string][]MetadataChange
	mutex              sync.Mutex
}

// NewMetadataManager initializes a new MetadataManager
func NewMetadataManager() *MetadataManager {
	return &MetadataManager{
		metadata:          make(map[string]Metadata),
		metadataHistories: make(map[string][]MetadataChange),
	}
}

// AddTokenMetadata adds metadata to a new token
func (mm *MetadataManager) AddTokenMetadata(tokenID string, metadata Metadata) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if _, exists := mm.metadata[tokenID]; exists {
		return fmt.Errorf("metadata for token ID %s already exists", tokenID)
	}

	mm.metadata[tokenID] = metadata
	mm.metadataHistories[tokenID] = []MetadataChange{
		{
			Timestamp:   time.Now(),
			OldMetadata: Metadata{},
			NewMetadata: metadata,
		},
	}

	return nil
}

// UpdateTokenMetadata updates the metadata of an existing token
func (mm *MetadataManager) UpdateTokenMetadata(tokenID string, newMetadata Metadata) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	oldMetadata, exists := mm.metadata[tokenID]
	if !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	mm.metadata[tokenID] = newMetadata
	mm.metadataHistories[tokenID] = append(mm.metadataHistories[tokenID], MetadataChange{
		Timestamp:   time.Now(),
		OldMetadata: oldMetadata,
		NewMetadata: newMetadata,
	})

	return nil
}

// GetTokenMetadata retrieves the metadata of a token by its ID
func (mm *MetadataManager) GetTokenMetadata(tokenID string) (Metadata, error) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	metadata, exists := mm.metadata[tokenID]
	if !exists {
		return Metadata{}, fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	return metadata, nil
}

// GetMetadataHistory retrieves the metadata history of a token
func (mm *MetadataManager) GetMetadataHistory(tokenID string) ([]MetadataChange, error) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	history, exists := mm.metadataHistories[tokenID]
	if !exists {
		return nil, fmt.Errorf("metadata history for token ID %s not found", tokenID)
	}

	return history, nil
}

// DeleteTokenMetadata deletes the metadata of a token
func (mm *MetadataManager) DeleteTokenMetadata(tokenID string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if _, exists := mm.metadata[tokenID]; !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	delete(mm.metadata, tokenID)
	delete(mm.metadataHistories, tokenID)

	return nil
}

// AddMetadataAttribute adds an attribute to a token's metadata
func (mm *MetadataManager) AddMetadataAttribute(tokenID, key, value string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	metadata, exists := mm.metadata[tokenID]
	if !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	if metadata.Attributes == nil {
		metadata.Attributes = make(map[string]string)
	}

	metadata.Attributes[key] = value
	mm.metadata[tokenID] = metadata

	return mm.logMetadataChange(tokenID, metadata)
}

// RemoveMetadataAttribute removes an attribute from a token's metadata
func (mm *MetadataManager) RemoveMetadataAttribute(tokenID, key string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	metadata, exists := mm.metadata[tokenID]
	if !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	delete(metadata.Attributes, key)
	mm.metadata[tokenID] = metadata

	return mm.logMetadataChange(tokenID, metadata)
}

// UpdateMetadataAttribute updates an attribute in a token's metadata
func (mm *MetadataManager) UpdateMetadataAttribute(tokenID, key, value string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	metadata, exists := mm.metadata[tokenID]
	if !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	metadata.Attributes[key] = value
	mm.metadata[tokenID] = metadata

	return mm.logMetadataChange(tokenID, metadata)
}

// logMetadataChange logs the metadata change
func (mm *MetadataManager) logMetadataChange(tokenID string, newMetadata Metadata) error {
	oldMetadata, exists := mm.metadata[tokenID]
	if !exists {
		return fmt.Errorf("metadata for token ID %s not found", tokenID)
	}

	mm.metadataHistories[tokenID] = append(mm.metadataHistories[tokenID], MetadataChange{
		Timestamp:   time.Now(),
		OldMetadata: oldMetadata,
		NewMetadata: newMetadata,
	})

	return nil
}
