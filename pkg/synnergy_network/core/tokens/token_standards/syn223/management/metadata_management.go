package management

import (
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/assets"
	"github.com/synnergy_network/utils"
)

// MetadataManager manages the metadata for SYN223 tokens.
type MetadataManager struct {
	mu            sync.RWMutex
	metadataStore *assets.MetadataStore
}

// NewMetadataManager initializes a new MetadataManager instance.
func NewMetadataManager(metadataStore *assets.MetadataStore) *MetadataManager {
	return &MetadataManager{
		metadataStore: metadataStore,
	}
}

// AddTokenMetadata adds new token metadata to the store.
func (mm *MetadataManager) AddTokenMetadata(metadata assets.TokenMetadata) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Validate metadata
	if metadata.ID == "" || metadata.Name == "" || metadata.Symbol == "" || metadata.TotalSupply == 0 {
		return errors.New("invalid token metadata")
	}

	// Add metadata to the store
	return mm.metadataStore.AddMetadata(metadata)
}

// UpdateTokenMetadata updates existing token metadata in the store.
func (mm *MetadataManager) UpdateTokenMetadata(metadata assets.TokenMetadata) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Validate metadata
	if metadata.ID == "" || metadata.Name == "" || metadata.Symbol == "" || metadata.TotalSupply == 0 {
		return errors.New("invalid token metadata")
	}

	// Update metadata in the store
	return mm.metadataStore.UpdateMetadata(metadata)
}

// GetTokenMetadata retrieves token metadata by ID.
func (mm *MetadataManager) GetTokenMetadata(id string) (assets.TokenMetadata, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Retrieve metadata from the store
	return mm.metadataStore.GetMetadata(id)
}

// DeleteTokenMetadata removes token metadata from the store.
func (mm *MetadataManager) DeleteTokenMetadata(id string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Remove metadata from the store
	return mm.metadataStore.DeleteMetadata(id)
}

// ListAllTokenMetadata lists all token metadata in the store.
func (mm *MetadataManager) ListAllTokenMetadata() ([]assets.TokenMetadata, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	metadataList := []assets.TokenMetadata{}
	for _, metadata := range mm.metadataStore.store {
		metadataList = append(metadataList, metadata)
	}

	return metadataList, nil
}

// ExportMetadata exports all token metadata to JSON format.
func (mm *MetadataManager) ExportMetadata() (string, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Export metadata to JSON
	return mm.metadataStore.ExportMetadata()
}

// ImportMetadata imports token metadata from JSON format.
func (mm *MetadataManager) ImportMetadata(jsonData string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Import metadata from JSON
	return mm.metadataStore.ImportMetadata(jsonData)
}

// VerifyTokenMetadata verifies the integrity and validity of token metadata.
func (mm *MetadataManager) VerifyTokenMetadata(id string) (bool, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Retrieve metadata
	metadata, err := mm.metadataStore.GetMetadata(id)
	if err != nil {
		return false, err
	}

	// Perform necessary validation checks
	if metadata.ID == "" || metadata.Name == "" || metadata.Symbol == "" || metadata.TotalSupply == 0 {
		return false, errors.New("invalid token metadata")
	}

	// Additional verification logic can be added here

	return true, nil
}

// EncryptMetadata encrypts token metadata using a specified encryption technique.
func (mm *MetadataManager) EncryptMetadata(metadata assets.TokenMetadata, passphrase string) (string, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Serialize metadata to JSON
	jsonData, err := utils.ToJSON(metadata)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptMetadata decrypts token metadata using a specified decryption technique.
func (mm *MetadataManager) DecryptMetadata(encryptedData, passphrase string) (assets.TokenMetadata, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return assets.TokenMetadata{}, err
	}

	// Deserialize JSON data to metadata
	var metadata assets.TokenMetadata
	err = utils.FromJSON(decryptedData, &metadata)
	if err != nil {
		return assets.TokenMetadata{}, err
	}

	return metadata, nil
}
