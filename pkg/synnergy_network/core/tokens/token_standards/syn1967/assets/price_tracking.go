package assets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// PriceData represents a single price data point
type PriceData struct {
	Timestamp  time.Time
	Price      float64
	Source     string
}

// PriceTracking represents the price tracking details of a commodity
type PriceTracking struct {
	CommodityID  string
	PriceHistory []PriceData
	AuditTrail   []AuditRecord
}

// AuditRecord represents a record of significant events
type AuditRecord struct {
	Timestamp time.Time
	Event     string
	Details   string
}

// PriceManager manages price tracking for commodities
type PriceManager struct {
	prices map[string]PriceTracking
}

// NewPriceManager creates a new price manager
func NewPriceManager() *PriceManager {
	return &PriceManager{prices: make(map[string]PriceTracking)}
}

// AddPriceData adds a new price data point
func (m *PriceManager) AddPriceData(commodityID string, price float64, source string) error {
	priceData := PriceData{
		Timestamp: time.Now(),
		Price:     price,
		Source:    source,
	}

	tracking, exists := m.prices[commodityID]
	if !exists {
		tracking = PriceTracking{
			CommodityID:  commodityID,
			PriceHistory: []PriceData{},
			AuditTrail:   []AuditRecord{},
		}
	}

	tracking.PriceHistory = append(tracking.PriceHistory, priceData)
	tracking.AuditTrail = append(tracking.AuditTrail, AuditRecord{
		Timestamp: time.Now(),
		Event:     "Price Update",
		Details:   fmt.Sprintf("Price updated to %f from source %s", price, source),
	})

	m.prices[commodityID] = tracking
	return nil
}

// GetPriceHistory retrieves the price history for a commodity
func (m *PriceManager) GetPriceHistory(commodityID string) ([]PriceData, error) {
	tracking, exists := m.prices[commodityID]
	if !exists {
		return nil, errors.New("commodity not found")
	}
	return tracking.PriceHistory, nil
}

// GetLatestPrice retrieves the latest price for a commodity
func (m *PriceManager) GetLatestPrice(commodityID string) (PriceData, error) {
	tracking, exists := m.prices[commodityID]
	if !exists {
		return PriceData{}, errors.New("commodity not found")
	}
	if len(tracking.PriceHistory) == 0 {
		return PriceData{}, errors.New("no price data available")
	}
	return tracking.PriceHistory[len(tracking.PriceHistory)-1], nil
}

// EncodeToJSON encodes price tracking data to JSON
func (m *PriceManager) EncodeToJSON(commodityID string) (string, error) {
	tracking, exists := m.prices[commodityID]
	if !exists {
		return "", errors.New("commodity not found")
	}

	jsonData, err := json.Marshal(tracking)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// DecodeFromJSON decodes price tracking data from JSON
func (m *PriceManager) DecodeFromJSON(jsonData string) (PriceTracking, error) {
	var tracking PriceTracking
	err := json.Unmarshal([]byte(jsonData), &tracking)
	if err != nil {
		return PriceTracking{}, err
	}

	m.prices[tracking.CommodityID] = tracking
	return tracking, nil
}

// SecureStorage handles secure storage of data
type SecureStorage struct {
	key []byte
}

// NewSecureStorage creates a new secure storage with a key
func NewSecureStorage(password string) *SecureStorage {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	key := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return &SecureStorage{key: key}
}

// Encrypt encrypts data using AES
func (s *SecureStorage) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

// Decrypt decrypts data using AES
func (s *SecureStorage) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// SecurePriceData securely stores price data
func (m *PriceManager) SecurePriceData(commodityID string, secureStorage *SecureStorage) (string, error) {
	tracking, exists := m.prices[commodityID]
	if !exists {
		return "", errors.New("commodity not found")
	}

	jsonData, err := json.Marshal(tracking)
	if err != nil {
		return "", err
	}

	encryptedData, err := secureStorage.Encrypt(jsonData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", encryptedData), nil
}

// RetrievePriceData retrieves and decrypts price data
func (m *PriceManager) RetrievePriceData(encryptedDataHex string, secureStorage *SecureStorage) (PriceTracking, error) {
	encryptedData, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return PriceTracking{}, err
	}

	jsonData, err := secureStorage.Decrypt(encryptedData)
	if err != nil {
		return PriceTracking{}, err
	}

	var tracking PriceTracking
	err = json.Unmarshal(jsonData, &tracking)
	if err != nil {
		return PriceTracking{}, err
	}

	m.prices[tracking.CommodityID] = tracking
	return tracking, nil
}

// ComplianceReport generates a compliance report for a commodity's price data
func (m *PriceManager) ComplianceReport(commodityID string) (string, error) {
	tracking, exists := m.prices[commodityID]
	if !exists {
		return "", errors.New("commodity not found")
	}

	report := fmt.Sprintf("Compliance Report for Commodity ID %s\n", tracking.CommodityID)
	report += "Price History:\n"
	for _, priceData := range tracking.PriceHistory {
		report += fmt.Sprintf("  - %s: %f from source %s\n", priceData.Timestamp.String(), priceData.Price, priceData.Source)
	}
	report += "Audit Trail:\n"
	for _, audit := range tracking.AuditTrail {
		report += fmt.Sprintf("  - %s: %s\n", audit.Timestamp.String(), audit.Event)
	}

	return report, nil
}
