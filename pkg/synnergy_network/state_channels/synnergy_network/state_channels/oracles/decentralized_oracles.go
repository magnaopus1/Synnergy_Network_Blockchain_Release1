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

// DecentralizedOracle represents a decentralized oracle for secure data feeds
type DecentralizedOracle struct {
	OracleID       string
	DataSources    []string
	CollectedData  map[string]interface{}
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	OracleActive   = "ACTIVE"
	OracleInactive = "INACTIVE"
	OracleError    = "ERROR"
)

// NewDecentralizedOracle initializes a new DecentralizedOracle instance
func NewDecentralizedOracle(oracleID string, dataSources []string) *DecentralizedOracle {
	return &DecentralizedOracle{
		OracleID:      oracleID,
		DataSources:   dataSources,
		CollectedData: make(map[string]interface{}),
		Timestamp:     time.Now(),
		Status:        OracleActive,
	}
}

// CollectData collects data from all the data sources
func (do *DecentralizedOracle) CollectData() error {
	do.lock.Lock()
	defer do.lock.Unlock()

	if do.Status != OracleActive {
		return errors.New("oracle is not active")
	}

	for _, source := range do.DataSources {
		data, err := do.fetchDataFromSource(source)
		if err != nil {
			do.Status = OracleError
			return err
		}
		do.CollectedData[source] = data
	}
	do.Timestamp = time.Now()
	return nil
}

// fetchDataFromSource simulates fetching data from a data source
func (do *DecentralizedOracle) fetchDataFromSource(source string) (interface{}, error) {
	// Simulated data fetching
	return fmt.Sprintf("Data from %s", source), nil
}

// DeactivateOracle deactivates the oracle
func (do *DecentralizedOracle) DeactivateOracle() error {
	do.lock.Lock()
	defer do.lock.Unlock()

	if do.Status != OracleActive {
		return errors.New("oracle is not active")
	}

	do.Status = OracleInactive
	do.Timestamp = time.Now()
	return nil
}

// EncryptOracleData encrypts the oracle data
func (do *DecentralizedOracle) EncryptOracleData(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s",
		do.OracleID, do.CollectedData, do.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptOracleData decrypts the oracle data
func (do *DecentralizedOracle) DecryptOracleData(encryptedData string, key []byte) error {
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
	if len(parts) != 3 {
		return errors.New("invalid encrypted data format")
	}

	do.OracleID = parts[0]
	do.CollectedData = utils.ParseData(parts[1])
	do.Status = parts[2]
	return nil
}

// GetOracleDetails returns the details of the decentralized oracle
func (do *DecentralizedOracle) GetOracleDetails() (string, map[string]interface{}, string) {
	do.lock.RLock()
	defer do.lock.RUnlock()
	return do.OracleID, do.CollectedData, do.Status
}

// ValidateOracle validates the decentralized oracle details
func (do *DecentralizedOracle) ValidateOracle() error {
	do.lock.RLock()
	defer do.lock.RUnlock()

	if do.OracleID == "" {
		return errors.New("oracle ID cannot be empty")
	}

	if len(do.DataSources) == 0 {
		return errors.New("data sources cannot be empty")
	}

	if len(do.CollectedData) == 0 {
		return errors.New("collected data cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the decentralized oracle
func (do *DecentralizedOracle) UpdateTimestamp() {
	do.lock.Lock()
	defer do.lock.Unlock()
	do.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the decentralized oracle
func (do *DecentralizedOracle) GetTimestamp() time.Time {
	do.lock.RLock()
	defer do.lock.RUnlock()
	return do.Timestamp
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

func (do *DecentralizedOracle) String() string {
	return fmt.Sprintf("OracleID: %s, Status: %s, Timestamp: %s", do.OracleID, do.Status, do.Timestamp)
}
