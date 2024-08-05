package data_collection

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/encryption"
	"github.com/synnergy_network/monitoring"
)

// DataPoint represents a single unit of collected data.
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Source    string    `json:"source"`
}

// DataGathering handles the collection and processing of data for predictive maintenance.
type DataGathering struct {
	Data      []DataPoint
	Mutex     sync.Mutex
	DataPath  string
	APIClient *http.Client
}

// NewDataGathering initializes a new DataGathering instance.
func NewDataGathering(dataPath string) *DataGathering {
	return &DataGathering{
		Data:      []DataPoint{},
		DataPath:  dataPath,
		APIClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// LoadData loads previously collected data from a file.
func (dg *DataGathering) LoadData() error {
	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()

	if _, err := os.Stat(dg.DataPath); os.IsNotExist(err) {
		return errors.New("data file does not exist")
	}

	dataBytes, err := ioutil.ReadFile(dg.DataPath)
	if err != nil {
		return fmt.Errorf("failed to read data file: %v", err)
	}

	if err := json.Unmarshal(dataBytes, &dg.Data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %v", err)
	}

	return nil
}

// SaveData saves the collected data to a file.
func (dg *DataGathering) SaveData() error {
	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()

	dataBytes, err := json.Marshal(dg.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	if err := ioutil.WriteFile(dg.DataPath, dataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write data file: %v", err)
	}

	return nil
}

// CollectDataFromAPI collects data from a specified API endpoint.
func (dg *DataGathering) CollectDataFromAPI(apiURL, source string) error {
	resp, err := dg.APIClient.Get(apiURL)
	if err != nil {
		return fmt.Errorf("failed to collect data from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response: %v", resp.Status)
	}

	var dataPoints []DataPoint
	if err := json.NewDecoder(resp.Body).Decode(&dataPoints); err != nil {
		return fmt.Errorf("failed to decode API response: %v", err)
	}

	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()

	for _, dp := range dataPoints {
		dp.Source = source
		dg.Data = append(dg.Data, dp)
	}

	if err := dg.SaveData(); err != nil {
		return err
	}

	return nil
}

// EncryptData encrypts the collected data using AES encryption.
func (dg *DataGathering) EncryptData(key []byte) ([]byte, error) {
	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()

	dataBytes, err := json.Marshal(dg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %v", err)
	}

	encryptedData, err := encryption.AESEncrypt(dataBytes, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	return encryptedData, nil
}

// DecryptData decrypts the encrypted data using AES encryption.
func (dg *DataGathering) DecryptData(encryptedData, key []byte) error {
	dataBytes, err := encryption.AESDecrypt(encryptedData, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	var data []DataPoint
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %v", err)
	}

	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()
	dg.Data = data

	return nil
}

// HashData generates a SHA-256 hash of the collected data.
func (dg *DataGathering) HashData() ([]byte, error) {
	dg.Mutex.Lock()
	defer dg.Mutex.Unlock()

	dataBytes, err := json.Marshal(dg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %v", err)
	}

	hash := sha256.Sum256(dataBytes)
	return hash[:], nil
}

// LogDataToBlockchain logs a hash of the collected data to the blockchain for integrity verification.
func (dg *DataGathering) LogDataToBlockchain() error {
	hash, err := dg.HashData()
	if err != nil {
		return fmt.Errorf("failed to hash data: %v", err)
	}

	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC(),
		"dataHash":  fmt.Sprintf("%x", hash),
		"source":    "DataGathering",
	}
	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %v", err)
	}

	if err := blockchain.LogActivity(logJSON); err != nil {
		return fmt.Errorf("failed to log activity to blockchain: %v", err)
	}

	return nil
}

// CollectAndLogData handles the full cycle of collecting data from an API, saving it, and logging it to the blockchain.
func (dg *DataGathering) CollectAndLogData(apiURL, source string, encryptionKey []byte) error {
	if err := dg.CollectDataFromAPI(apiURL, source); err != nil {
		return err
	}

	if err := dg.LogDataToBlockchain(); err != nil {
		return err
	}

	encryptedData, err := dg.EncryptData(encryptionKey)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(dg.DataPath+".enc", encryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted data file: %v", err)
	}

	return nil
}

// GenerateSecureKey generates a secure random key for encryption.
func GenerateSecureKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate secure key: %v", err)
	}
	return key, nil
}
