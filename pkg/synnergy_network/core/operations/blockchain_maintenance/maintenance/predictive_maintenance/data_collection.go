package predictive_maintenance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/argon2"
)

// Config represents the configuration settings for DataCollection.
type Config struct {
	EncryptionKey   string
	Logging         bool
	DBConnection    string
	Authentication  bool
	DataCollectionInterval time.Duration
}

// DataCollection contains methods for performing secure and efficient data collection.
type DataCollection struct {
	encryptionKey []byte
	logging       bool
	dbConnection  string
	authentication bool
	collectionInterval time.Duration
}

// NewDataCollection creates a new instance of DataCollection with the given configuration.
func NewDataCollection(config Config) *DataCollection {
	keyHash := sha256.Sum256([]byte(config.EncryptionKey))
	return &DataCollection{
		encryptionKey:     keyHash[:],
		logging:           config.Logging,
		dbConnection:      config.DBConnection,
		authentication:    config.Authentication,
		collectionInterval: config.DataCollectionInterval,
	}
}

// EncryptData encrypts the input data using AES encryption.
func (dc *DataCollection) EncryptData(plainText string) (string, error) {
	block, err := aes.NewCipher(dc.encryptionKey)
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

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptData decrypts the input data using AES encryption.
func (dc *DataCollection) DecryptData(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dc.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// CollectData performs the data collection process from IoT devices or other sources.
func (dc *DataCollection) CollectData(source string) ([]string, error) {
	// Placeholder for real data collection logic
	// This can involve making API calls, reading from sensors, etc.
	data := []string{"data1", "data2", "data3"}

	if dc.logging {
		log.Printf("Collected data from source %s: %v\n", source, data)
	}

	encryptedData := make([]string, len(data))
	for i, datum := range data {
		encDatum, err := dc.EncryptData(datum)
		if err != nil {
			return nil, err
		}
		encryptedData[i] = encDatum
	}

	return encryptedData, nil
}

// SaveData saves the collected data to the database securely.
func (dc *DataCollection) SaveData(data []string) error {
	// Placeholder for saving data securely
	// This can involve storing in a database or a file system
	if dc.logging {
		log.Printf("Saving data to the database: %v\n", data)
	}
	return nil
}

// AuthenticateRequest authenticates incoming requests if authentication is enabled.
func (dc *DataCollection) AuthenticateRequest(r *http.Request) bool {
	if !dc.authentication {
		return true
	}

	// Placeholder for real authentication logic
	// This can involve checking API keys, tokens, etc.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	expectedAuth := "Bearer " + string(dc.encryptionKey) // Simplified example
	return authHeader == expectedAuth
}

// StartDataCollection initiates the periodic data collection process.
func (dc *DataCollection) StartDataCollection(source string) {
	ticker := time.NewTicker(dc.collectionInterval)
	defer ticker.Stop()

	for range ticker.C {
		data, err := dc.CollectData(source)
		if err != nil {
			log.Printf("Error collecting data: %v\n", err)
			continue
		}

		if err := dc.SaveData(data); err != nil {
			log.Printf("Error saving data: %v\n", err)
		}
	}
}

// HashPassword securely hashes a password using Argon2.
func (dc *DataCollection) HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(append(salt, hash...)), nil
}

// VerifyPassword verifies a hashed password using Argon2.
func (dc *DataCollection) VerifyPassword(password, hashedPassword string) (bool, error) {
	hashBytes, err := base64.StdEncoding.DecodeString(hashedPassword)
	if err != nil {
		return false, err
	}

	salt := hashBytes[:16]
	hash := hashBytes[16:]

	newHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return subtle.ConstantTimeCompare(hash, newHash) == 1, nil
}
