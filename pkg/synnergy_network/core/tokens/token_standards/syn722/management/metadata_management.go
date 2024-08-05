package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn722/security"
)

// MetadataManager manages the metadata of SYN722 tokens.
type MetadataManager struct {
	mu      sync.Mutex
	Metadata map[string]*assets.Metadata
}

// NewMetadataManager creates a new instance of MetadataManager.
func NewMetadataManager() *MetadataManager {
	return &MetadataManager{
		Metadata: make(map[string]*assets.Metadata),
	}
}

// AddMetadata adds metadata to a SYN722 token.
func (mm *MetadataManager) AddMetadata(tokenID, owner string, mode string, quantity int, attributes map[string]string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if _, exists := mm.Metadata[tokenID]; exists {
		return errors.New("metadata already exists for this token")
	}

	metadata := assets.NewMetadata(tokenID, owner, mode, quantity, attributes)
	if err := metadata.ValidateMetadata(); err != nil {
		return err
	}

	mm.Metadata[tokenID] = metadata
	return nil
}

// UpdateMetadata updates the metadata of a SYN722 token.
func (mm *MetadataManager) UpdateMetadata(tokenID string, attributes map[string]string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return errors.New("metadata not found for this token")
	}

	if metadata.Encrypted {
		return errors.New("cannot update encrypted metadata")
	}

	if err := metadata.UpdateMetadata(attributes); err != nil {
		return err
	}

	return nil
}

// GetMetadata retrieves the metadata of a SYN722 token.
func (mm *MetadataManager) GetMetadata(tokenID string) (*assets.Metadata, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return nil, errors.New("metadata not found for this token")
	}

	return metadata, nil
}

// DeleteMetadata deletes the metadata of a SYN722 token.
func (mm *MetadataManager) DeleteMetadata(tokenID string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if _, exists := mm.Metadata[tokenID]; !exists {
		return errors.New("metadata not found for this token")
	}

	delete(mm.Metadata, tokenID)
	return nil
}

// EncryptMetadata encrypts the metadata of a SYN722 token using AES encryption.
func (mm *MetadataManager) EncryptMetadata(tokenID, key string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return errors.New("metadata not found for this token")
	}

	if metadata.Encrypted {
		return errors.New("metadata is already encrypted")
	}

	if err := metadata.EncryptMetadata(key); err != nil {
		return err
	}

	return nil
}

// DecryptMetadata decrypts the metadata of a SYN722 token using AES decryption.
func (mm *MetadataManager) DecryptMetadata(tokenID, key string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return errors.New("metadata not found for this token")
	}

	if !metadata.Encrypted {
		return errors.New("metadata is not encrypted")
	}

	if err := metadata.DecryptMetadata(key); err != nil {
		return err
	}

	return nil
}

// LogMetadataChange logs changes to the metadata of a SYN722 token.
func (mm *MetadataManager) LogMetadataChange(tokenID, action, details string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return errors.New("metadata not found for this token")
	}

	entry := assets.AssetHistoryEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
	}
	metadata.History = append(metadata.History, entry)
	return nil
}

// DisplayMetadata provides a JSON representation of the metadata for easy viewing.
func (mm *MetadataManager) DisplayMetadata(tokenID string) (string, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	metadata, exists := mm.Metadata[tokenID]
	if !exists {
		return "", errors.New("metadata not found for this token")
	}

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
