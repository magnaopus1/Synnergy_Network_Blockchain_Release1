package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1967/ledger"
	"golang.org/x/crypto/scrypt"
)

// Storage struct representing the storage for SYN1967 tokens.
type Storage struct {
	data map[string]string
	key  []byte
}

// NewStorage creates a new instance of Storage.
func NewStorage(password string) (*Storage, error) {
	key, err := deriveKey(password)
	if err != nil {
		return nil, err
	}

	return &Storage{
		data: make(map[string]string),
		key:  key,
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
func (s *Storage) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(s.key)
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
func (s *Storage) Decrypt(ciphertext string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(s.key)
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

// Save stores data in the storage.
func (s *Storage) Save(key string, value interface{}) error {
	plaintext, err := encode(value)
	if err != nil {
		return err
	}

	ciphertext, err := s.Encrypt(plaintext)
	if err != nil {
		return err
	}

	s.data[key] = ciphertext
	return nil
}

// Load retrieves data from the storage.
func (s *Storage) Load(key string, value interface{}) error {
	ciphertext, exists := s.data[key]
	if !exists {
		return errors.New("key not found")
	}

	plaintext, err := s.Decrypt(ciphertext)
	if err != nil {
		return err
	}

	return decode(plaintext, value)
}

// encode encodes data to a byte array.
func encode(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(value)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decode decodes data from a byte array.
func decode(data []byte, value interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(value)
}

// SaveCommodityMetadata saves commodity metadata in the storage.
func (s *Storage) SaveCommodityMetadata(tokenID string, metadata assets.CommodityMetadata) error {
	return s.Save(fmt.Sprintf("commodity_metadata_%s", tokenID), metadata)
}

// LoadCommodityMetadata loads commodity metadata from the storage.
func (s *Storage) LoadCommodityMetadata(tokenID string) (*assets.CommodityMetadata, error) {
	var metadata assets.CommodityMetadata
	err := s.Load(fmt.Sprintf("commodity_metadata_%s", tokenID), &metadata)
	if err != nil {
		return nil, err
	}
	return &metadata, nil
}

// SaveOwnershipRecord saves an ownership record in the storage.
func (s *Storage) SaveOwnershipRecord(tokenID string, record ledger.OwnershipRecord) error {
	return s.Save(fmt.Sprintf("ownership_record_%s", tokenID), record)
}

// LoadOwnershipRecord loads an ownership record from the storage.
func (s *Storage) LoadOwnershipRecord(tokenID string) (*ledger.OwnershipRecord, error) {
	var record ledger.OwnershipRecord
	err := s.Load(fmt.Sprintf("ownership_record_%s", tokenID), &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// SavePriceData saves price data in the storage.
func (s *Storage) SavePriceData(tokenID string, priceData assets.PriceData) error {
	return s.Save(fmt.Sprintf("price_data_%s", tokenID), priceData)
}

// LoadPriceData loads price data from the storage.
func (s *Storage) LoadPriceData(tokenID string) (*assets.PriceData, error) {
	var priceData assets.PriceData
	err := s.Load(fmt.Sprintf("price_data_%s", tokenID), &priceData)
	if err != nil {
		return nil, err
	}
	return &priceData, nil
}

// SaveEventLog saves an event log in the storage.
func (s *Storage) SaveEventLog(eventID string, eventData assets.EventLog) error {
	return s.Save(fmt.Sprintf("event_log_%s", eventID), eventData)
}

// LoadEventLog loads an event log from the storage.
func (s *Storage) LoadEventLog(eventID string) (*assets.EventLog, error) {
	var eventData assets.EventLog
	err := s.Load(fmt.Sprintf("event_log_%s", eventID), &eventData)
	if err != nil {
		return nil, err
	}
	return &eventData, nil
}

// Additional save and load methods for other data structures.
