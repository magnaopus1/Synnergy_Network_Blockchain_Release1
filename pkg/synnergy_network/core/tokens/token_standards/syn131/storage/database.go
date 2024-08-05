package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AssetDatabase represents the storage for assets in the SYN131 token standard
type AssetDatabase struct {
	Assets map[string]AssetData
}

// AssetData represents the data structure for an asset
type AssetData struct {
	ID            string                 `json:"id"`
	Owner         string                 `json:"owner"`
	Metadata      map[string]interface{} `json:"metadata"`
	EncryptedData string                 `json:"encrypted_data"`
	Timestamp     time.Time              `json:"timestamp"`
}

// NewAssetDatabase initializes a new AssetDatabase
func NewAssetDatabase() *AssetDatabase {
	return &AssetDatabase{
		Assets: make(map[string]AssetData),
	}
}

// AddAsset adds a new asset to the database
func (db *AssetDatabase) AddAsset(asset AssetData) error {
	if _, exists := db.Assets[asset.ID]; exists {
		return errors.New("asset with this ID already exists")
	}
	db.Assets[asset.ID] = asset
	return nil
}

// UpdateAsset updates an existing asset in the database
func (db *AssetDatabase) UpdateAsset(asset AssetData) error {
	if _, exists := db.Assets[asset.ID]; !exists {
		return errors.New("asset not found")
	}
	db.Assets[asset.ID] = asset
	return nil
}

// GetAsset retrieves an asset by its ID
func (db *AssetDatabase) GetAsset(id string) (AssetData, error) {
	asset, exists := db.Assets[id]
	if !exists {
		return AssetData{}, errors.New("asset not found")
	}
	return asset, nil
}

// DeleteAsset deletes an asset by its ID
func (db *AssetDatabase) DeleteAsset(id string) error {
	if _, exists := db.Assets[id]; !exists {
		return errors.New("asset not found")
	}
	delete(db.Assets, id)
	return nil
}

// EncryptData encrypts data using AES with Scrypt for key derivation
func EncryptData(plaintext string, passphrase string) (string, string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(salt), nil
}

// DecryptData decrypts data using AES with Scrypt for key derivation
func DecryptData(ciphertextHex string, passphrase string, saltHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ExampleUsage demonstrates how to use the AssetDatabase with encryption and decryption
func ExampleUsage() {
	db := NewAssetDatabase()

	// Encrypt data
	encryptedData, salt, err := EncryptData("This is a secret asset", "passphrase123")
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	// Create a new asset
	asset := AssetData{
		ID:            "asset_001",
		Owner:         "owner_001",
		Metadata:      map[string]interface{}{"type": "digital_asset"},
		EncryptedData: encryptedData,
		Timestamp:     time.Now(),
	}

	// Add asset to database
	if err := db.AddAsset(asset); err != nil {
		fmt.Println("Error adding asset:", err)
		return
	}

	// Retrieve asset from database
	retrievedAsset, err := db.GetAsset("asset_001")
	if err != nil {
		fmt.Println("Error retrieving asset:", err)
		return
	}

	// Decrypt data
	decryptedData, err := DecryptData(retrievedAsset.EncryptedData, "passphrase123", salt)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Println("Decrypted Data:", decryptedData)
}
