package oracles

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// RealTimeDataFeed represents a real-time data feed from a decentralized oracle
type RealTimeDataFeed struct {
	FeedID         string
	OracleID       string
	DataPoints     map[string]interface{}
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	FeedActive   = "ACTIVE"
	FeedInactive = "INACTIVE"
	FeedError    = "ERROR"
)

// NewRealTimeDataFeed initializes a new RealTimeDataFeed instance
func NewRealTimeDataFeed(feedID, oracleID string) *RealTimeDataFeed {
	return &RealTimeDataFeed{
		FeedID:     feedID,
		OracleID:   oracleID,
		DataPoints: make(map[string]interface{}),
		Timestamp:  time.Now(),
		Status:     FeedActive,
	}
}

// UpdateDataPoints updates the data points in the real-time data feed
func (rtf *RealTimeDataFeed) UpdateDataPoints(newDataPoints map[string]interface{}) error {
	rtf.lock.Lock()
	defer rtf.lock.Unlock()

	if rtf.Status != FeedActive {
		return errors.New("feed is not active")
	}

	for key, value := range newDataPoints {
		rtf.DataPoints[key] = value
	}
	rtf.Timestamp = time.Now()
	return nil
}

// DeactivateFeed deactivates the real-time data feed
func (rtf *RealTimeDataFeed) DeactivateFeed() error {
	rtf.lock.Lock()
	defer rtf.lock.Unlock()

	if rtf.Status != FeedActive {
		return errors.New("feed is not active")
	}

	rtf.Status = FeedInactive
	rtf.Timestamp = time.Now()
	return nil
}

// EncryptFeedData encrypts the real-time data feed details
func (rtf *RealTimeDataFeed) EncryptFeedData(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s",
		rtf.FeedID, rtf.OracleID, rtf.DataPoints, rtf.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptFeedData decrypts the real-time data feed details
func (rtf *RealTimeDataFeed) DecryptFeedData(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	rtf.FeedID = parts[0]
	rtf.OracleID = parts[1]
	rtf.DataPoints = utils.ParseData(parts[2])
	rtf.Status = parts[3]
	return nil
}

// GetFeedDetails returns the details of the real-time data feed
func (rtf *RealTimeDataFeed) GetFeedDetails() (string, string, map[string]interface{}, string) {
	rtf.lock.RLock()
	defer rtf.lock.RUnlock()
	return rtf.FeedID, rtf.OracleID, rtf.DataPoints, rtf.Status
}

// ValidateFeed validates the real-time data feed details
func (rtf *RealTimeDataFeed) ValidateFeed() error {
	rtf.lock.RLock()
	defer rtf.lock.RUnlock()

	if rtf.FeedID == "" || rtf.OracleID == "" {
		return errors.New("feed and oracle IDs cannot be empty")
	}

	if len(rtf.DataPoints) == 0 {
		return errors.New("data points cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the real-time data feed
func (rtf *RealTimeDataFeed) UpdateTimestamp() {
	rtf.lock.Lock()
	defer rtf.lock.Unlock()
	rtf.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the real-time data feed
func (rtf *RealTimeDataFeed) GetTimestamp() time.Time {
	rtf.lock.RLock()
	defer rtf.lock.RUnlock()
	return rtf.Timestamp
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (rtf *RealTimeDataFeed) String() string {
	return fmt.Sprintf("FeedID: %s, OracleID: %s, Status: %s, Timestamp: %s", rtf.FeedID, rtf.OracleID, rtf.Status, rtf.Timestamp)
}
