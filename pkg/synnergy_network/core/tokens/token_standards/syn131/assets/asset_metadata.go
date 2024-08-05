package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AssetMetadata represents metadata associated with an intangible asset.
type AssetMetadata struct {
	ID          string
	Name        string
	Description string
	Owner       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Encrypted   bool
}

// MetadataManager handles the operations related to asset metadata management.
type MetadataManager struct {
	MetadataStore map[string]*AssetMetadata
}

// NewMetadataManager initializes a new MetadataManager.
func NewMetadataManager() *MetadataManager {
	return &MetadataManager{
		MetadataStore: make(map[string]*AssetMetadata),
	}
}

// AddMetadata adds new metadata to the manager.
func (mm *MetadataManager) AddMetadata(id, name, description, owner string, encrypted bool) (*AssetMetadata, error) {
	if _, exists := mm.MetadataStore[id]; exists {
		return nil, fmt.Errorf("metadata with ID %s already exists", id)
	}
	metadata := &AssetMetadata{
		ID:          id,
		Name:        name,
		Description: description,
		Owner:       owner,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Encrypted:   encrypted,
	}
	mm.MetadataStore[id] = metadata
	return metadata, nil
}

// UpdateMetadata updates the metadata information for a given asset ID.
func (mm *MetadataManager) UpdateMetadata(id, name, description, owner string, encrypted bool) (*AssetMetadata, error) {
	metadata, exists := mm.MetadataStore[id]
	if !exists {
		return nil, fmt.Errorf("metadata with ID %s not found", id)
	}
	metadata.Name = name
	metadata.Description = description
	metadata.Owner = owner
	metadata.UpdatedAt = time.Now()
	metadata.Encrypted = encrypted
	return metadata, nil
}

// GetMetadata retrieves the metadata for a given asset ID.
func (mm *MetadataManager) GetMetadata(id string) (*AssetMetadata, error) {
	metadata, exists := mm.MetadataStore[id]
	if !exists {
		return nil, fmt.Errorf("metadata with ID %s not found", id)
	}
	return metadata, nil
}

// EncryptMetadata encrypts the metadata using AES-GCM with a key derived from the given password.
func (mm *MetadataManager) EncryptMetadata(id, password string) (string, error) {
	metadata, err := mm.GetMetadata(id)
	if err != nil {
		return "", err
	}

	plaintext := fmt.Sprintf("%s:%s:%s:%s", metadata.ID, metadata.Name, metadata.Description, metadata.Owner)
	ciphertext, err := Encrypt(plaintext, password)
	if err != nil {
		return "", err
	}

	metadata.Encrypted = true
	return ciphertext, nil
}

// DecryptMetadata decrypts the metadata using AES-GCM with a key derived from the given password.
func (mm *MetadataManager) DecryptMetadata(id, password, ciphertext string) (*AssetMetadata, error) {
	plaintext, err := Decrypt(ciphertext, password)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(plaintext, ":")
	if len(parts) != 4 {
		return nil, errors.New("invalid plaintext format")
	}

	metadata, err := mm.GetMetadata(id)
	if err != nil {
		return nil, err
	}

	metadata.ID = parts[0]
	metadata.Name = parts[1]
	metadata.Description = parts[2]
	metadata.Owner = parts[3]
	metadata.Encrypted = false

	return metadata, nil
}

// GenerateSalt generates a new random salt.
func GenerateSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// DeriveKey derives a key from the given password and salt using scrypt.
func DeriveKey(password, salt string) ([]byte, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return nil, err
	}
	return scrypt.Key([]byte(password), saltBytes, 32768, 8, 1, 32)
}

// Encrypt encrypts the given plaintext using AES-GCM.
func Encrypt(plaintext, password string) (string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return fmt.Sprintf("%s:%s", salt, hex.EncodeToString(ciphertext)), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM.
func Decrypt(ciphertext, password string) (string, error) {
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid ciphertext format")
	}

	salt := parts[0]
	ciphertextBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashData hashes the given data using SHA-256.
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
