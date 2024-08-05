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
	"time"

	"golang.org/x/crypto/scrypt"
)

// Asset represents an intangible asset with associated metadata.
type IntangibleAsset struct {
	ID              string
	Name            string
	Description     string
	Owner           string
	Valuation       float64
	LastValuation   time.Time
	TransferHistory []TransferRecord
}

// TransferRecord represents a record of asset transfer.
type TransferRecord struct {
	From      string
	To        string
	Timestamp time.Time
}

// AssetManager handles the operations related to asset tracking.
type AssetManager struct {
	Assets map[string]*Asset
}

// NewAssetManager initializes a new AssetManager.
func NewAssetManager() *AssetManager {
	return &AssetManager{
		Assets: make(map[string]*Asset),
	}
}

// CreateAsset creates a new asset and adds it to the manager.
func (am *AssetManager) CreateAsset(id, name, description, owner string, valuation float64) (*Asset, error) {
	if _, exists := am.Assets[id]; exists {
		return nil, fmt.Errorf("asset with ID %s already exists", id)
	}
	asset := &Asset{
		ID:            id,
		Name:          name,
		Description:   description,
		Owner:         owner,
		Valuation:     valuation,
		LastValuation: time.Now(),
	}
	am.Assets[id] = asset
	return asset, nil
}

// TransferOwnership transfers ownership of an asset to a new owner.
func (am *AssetManager) TransferOwnership(assetID, newOwner string) error {
	asset, exists := am.Assets[assetID]
	if !exists {
		return fmt.Errorf("asset with ID %s not found", assetID)
	}

	transferRecord := TransferRecord{
		From:      asset.Owner,
		To:        newOwner,
		Timestamp: time.Now(),
	}

	asset.Owner = newOwner
	asset.TransferHistory = append(asset.TransferHistory, transferRecord)
	return nil
}

// GetAsset returns the asset with the given ID.
func (am *AssetManager) GetAsset(assetID string) (*Asset, error) {
	asset, exists := am.Assets[assetID]
	if !exists {
		return nil, fmt.Errorf("asset with ID %s not found", assetID)
	}
	return asset, nil
}

// UpdateValuation updates the valuation of an asset.
func (am *AssetManager) UpdateValuation(assetID string, newValuation float64) error {
	asset, exists := am.Assets[assetID]
	if !exists {
		return fmt.Errorf("asset with ID %s not found", assetID)
	}

	asset.Valuation = newValuation
	asset.LastValuation = time.Now()
	return nil
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

