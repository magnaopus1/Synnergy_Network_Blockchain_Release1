package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/security"
	"github.com/synnergy_network/utils"
)

// AssetMetadata represents the metadata structure for an asset
type AssetMetadata struct {
	AssetID      string
	Description  string
	Images       []string
	Documents    []string
	CustomFields map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// MetadataManager handles asset metadata operations
type MetadataManager struct {
	MetadataStore map[string]AssetMetadata
	Mutex         sync.Mutex
}

// NewMetadataManager creates a new instance of MetadataManager
func NewMetadataManager() *MetadataManager {
	return &MetadataManager{
		MetadataStore: make(map[string]AssetMetadata),
	}
}

// AddMetadata adds new metadata for an asset
func (mm *MetadataManager) AddMetadata(assetID, description string, images, documents []string, customFields map[string]string) error {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	if _, exists := mm.MetadataStore[assetID]; exists {
		return errors.New("metadata for asset already exists")
	}

	mm.MetadataStore[assetID] = AssetMetadata{
		AssetID:      assetID,
		Description:  description,
		Images:       images,
		Documents:    documents,
		CustomFields: customFields,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	return nil
}

// UpdateMetadata updates existing metadata for an asset
func (mm *MetadataManager) UpdateMetadata(assetID, description string, images, documents []string, customFields map[string]string) error {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	metadata, exists := mm.MetadataStore[assetID]
	if !exists {
		return errors.New("metadata for asset not found")
	}

	metadata.Description = description
	metadata.Images = images
	metadata.Documents = documents
	metadata.CustomFields = customFields
	metadata.UpdatedAt = time.Now()
	mm.MetadataStore[assetID] = metadata
	return nil
}

// RemoveMetadata removes metadata for an asset
func (mm *MetadataManager) RemoveMetadata(assetID string) error {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	if _, exists := mm.MetadataStore[assetID]; !exists {
		return errors.New("metadata for asset not found")
	}

	delete(mm.MetadataStore, assetID)
	return nil
}

// GetMetadata retrieves metadata for an asset
func (mm *MetadataManager) GetMetadata(assetID string) (AssetMetadata, error) {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	metadata, exists := mm.MetadataStore[assetID]
	if !exists {
		return AssetMetadata{}, errors.New("metadata for asset not found")
	}
	return metadata, nil
}

// SaveMetadata saves the metadata store to persistent storage
func (mm *MetadataManager) SaveMetadata(storagePath string) error {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	data, err := json.Marshal(mm.MetadataStore)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadMetadata loads the metadata store from persistent storage
func (mm *MetadataManager) LoadMetadata(storagePath string) error {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &mm.MetadataStore)
	if err != nil {
		return err
	}
	return nil
}

// VerifyMetadataSignature verifies the cryptographic signature of the metadata
func (mm *MetadataManager) VerifyMetadataSignature(assetID string, signature []byte) (bool, error) {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	metadata, exists := mm.MetadataStore[assetID]
	if !exists {
		return false, errors.New("metadata for asset not found")
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return false, err
	}

	verified, err := security.VerifySignature(data, signature)
	if err != nil {
		return false, err
	}
	return verified, nil
}

// GenerateMetadataSignature generates a cryptographic signature for the metadata
func (mm *MetadataManager) GenerateMetadataSignature(assetID string) ([]byte, error) {
	mm.Mutex.Lock()
	defer mm.Mutex.Unlock()

	metadata, exists := mm.MetadataStore[assetID]
	if !exists {
		return nil, errors.New("metadata for asset not found")
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	signature, err := security.GenerateSignature(data)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
