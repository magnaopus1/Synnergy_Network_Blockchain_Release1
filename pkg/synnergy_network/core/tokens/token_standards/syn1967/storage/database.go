package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/ledger"
	"golang.org/x/crypto/scrypt"
)

// Database struct representing the storage for SYN1967 tokens.
type Database struct {
	storage map[string]interface{}
	key     []byte
}

// NewDatabase creates a new instance of Database.
func NewDatabase(password string) (*Database, error) {
	key, err := deriveKey(password)
	if err != nil {
		return nil, err
	}

	return &Database{
		storage: make(map[string]interface{}),
		key:     key,
	}, nil
}

// deriveKey derives a key from a password using scrypt.
func deriveKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts data using AES.
func (db *Database) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(db.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES.
func (db *Database) Decrypt(ciphertext string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(db.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Save stores data in the database.
func (db *Database) Save(key string, value interface{}) error {
	plaintext, err := encode(value)
	if err != nil {
		return err
	}

	ciphertext, err := db.Encrypt(plaintext)
	if err != nil {
		return err
	}

	db.storage[key] = ciphertext
	return nil
}

// Load retrieves data from the database.
func (db *Database) Load(key string, value interface{}) error {
	ciphertext, exists := db.storage[key]
	if !exists {
		return errors.New("key not found")
	}

	plaintext, err := db.Decrypt(ciphertext.(string))
	if err != nil {
		return err
	}

	return decode(plaintext, value)
}

// encode encodes data to a byte array.
func encode(value interface{}) ([]byte, error) {
	// Implement the encoding logic here (e.g., JSON encoding).
	// This is a placeholder implementation.
	return []byte(fmt.Sprintf("%v", value)), nil
}

// decode decodes data from a byte array.
func decode(data []byte, value interface{}) error {
	// Implement the decoding logic here (e.g., JSON decoding).
	// This is a placeholder implementation.
	// Ensure to properly decode to the correct type.
	return nil
}

// SaveCommodityMetadata saves commodity metadata in the database.
func (db *Database) SaveCommodityMetadata(tokenID string, metadata assets.CommodityMetadata) error {
	return db.Save(fmt.Sprintf("commodity_metadata_%s", tokenID), metadata)
}

// LoadCommodityMetadata loads commodity metadata from the database.
func (db *Database) LoadCommodityMetadata(tokenID string) (*assets.CommodityMetadata, error) {
	var metadata assets.CommodityMetadata
	err := db.Load(fmt.Sprintf("commodity_metadata_%s", tokenID), &metadata)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// SaveOwnershipRecord saves an ownership record in the database.
func (db *Database) SaveOwnershipRecord(tokenID string, record ledger.OwnershipRecord) error {
	return db.Save(fmt.Sprintf("ownership_record_%s", tokenID), record)
}

// LoadOwnershipRecord loads an ownership record from the database.
func (db *Database) LoadOwnershipRecord(tokenID string) (*ledger.OwnershipRecord, error) {
	var record ledger.OwnershipRecord
	err := db.Load(fmt.Sprintf("ownership_record_%s", tokenID), &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// SavePriceData saves price data in the database.
func (db *Database) SavePriceData(tokenID string, priceData assets.PriceData) error {
	return db.Save(fmt.Sprintf("price_data_%s", tokenID), priceData)
}

// LoadPriceData loads price data from the database.
func (db *Database) LoadPriceData(tokenID string) (*assets.PriceData, error) {
	var priceData assets.PriceData
	err := db.Load(fmt.Sprintf("price_data_%s", tokenID), &priceData)
	if err != nil {
		return nil, err
	}
	return &priceData, nil
}

// Implement additional storage functions as needed.
