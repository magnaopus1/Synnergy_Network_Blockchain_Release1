package data_collection

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/synnergy_network/encryption"
)

// DataPreprocessor handles the preprocessing of raw data for predictive maintenance models.
type DataPreprocessor struct {
	RawDataPath      string
	ProcessedDataPath string
	Mutex            sync.Mutex
}

// NewDataPreprocessor initializes a new DataPreprocessor instance.
func NewDataPreprocessor(rawDataPath, processedDataPath string) *DataPreprocessor {
	return &DataPreprocessor{
		RawDataPath:       rawDataPath,
		ProcessedDataPath: processedDataPath,
	}
}

// LoadRawData loads raw data from a file.
func (dp *DataPreprocessor) LoadRawData() ([]byte, error) {
	dp.Mutex.Lock()
	defer dp.Mutex.Unlock()

	data, err := ioutil.ReadFile(dp.RawDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw data file: %v", err)
	}
	return data, nil
}

// SaveProcessedData saves processed data to a file.
func (dp *DataPreprocessor) SaveProcessedData(data []byte) error {
	dp.Mutex.Lock()
	defer dp.Mutex.Unlock()

	err := ioutil.WriteFile(dp.ProcessedDataPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write processed data file: %v", err)
	}
	return nil
}

// CleanData removes duplicates and invalid entries from the raw data.
func (dp *DataPreprocessor) CleanData(rawData []byte) ([]byte, error) {
	var data []map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw data: %v", err)
	}

	// Remove duplicates and invalid entries
	cleanedData := removeDuplicates(data)
	cleanedData = removeInvalidEntries(cleanedData)

	cleanedDataBytes, err := json.Marshal(cleanedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cleaned data: %v", err)
	}
	return cleanedDataBytes, nil
}

// NormalizeData normalizes the data to a standard scale.
func (dp *DataPreprocessor) NormalizeData(cleanedData []byte) ([]byte, error) {
	var data []map[string]interface{}
	if err := json.Unmarshal(cleanedData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cleaned data: %v", err)
	}

	// Normalize data here (example: min-max scaling)
	normalizedData := normalizeValues(data)

	normalizedDataBytes, err := json.Marshal(normalizedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal normalized data: %v", err)
	}
	return normalizedDataBytes, nil
}

// EncryptData encrypts the processed data using AES encryption.
func (dp *DataPreprocessor) EncryptData(data []byte, key []byte) ([]byte, error) {
	encryptedData, err := encryption.AESEncrypt(data, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}
	return encryptedData, nil
}

// HashData generates a SHA-256 hash of the processed data.
func (dp *DataPreprocessor) HashData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// ProcessData handles the entire preprocessing workflow from loading raw data to saving processed data.
func (dp *DataPreprocessor) ProcessData(encryptionKey []byte) error {
	// Load raw data
	rawData, err := dp.LoadRawData()
	if err != nil {
		return err
	}

	// Clean data
	cleanedData, err := dp.CleanData(rawData)
	if err != nil {
		return err
	}

	// Normalize data
	normalizedData, err := dp.NormalizeData(cleanedData)
	if err != nil {
		return err
	}

	// Encrypt data
	encryptedData, err := dp.EncryptData(normalizedData, encryptionKey)
	if err != nil {
		return err
	}

	// Save processed data
	if err := dp.SaveProcessedData(encryptedData); err != nil {
		return err
	}

	// Hash data for integrity verification
	_, err = dp.HashData(normalizedData)
	if err != nil {
		return err
	}

	return nil
}

// removeDuplicates removes duplicate entries from the data.
func removeDuplicates(data []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]bool)
	var uniqueData []map[string]interface{}

	for _, entry := range data {
		entryStr := fmt.Sprintf("%v", entry)
		if _, exists := seen[entryStr]; !exists {
			seen[entryStr] = true
			uniqueData = append(uniqueData, entry)
		}
	}
	return uniqueData
}

// removeInvalidEntries removes invalid entries based on predefined criteria.
func removeInvalidEntries(data []map[string]interface{}) []map[string]interface{} {
	var validData []map[string]interface{}

	for _, entry := range data {
		if isValidEntry(entry) {
			validData = append(validData, entry)
		}
	}
	return validData
}

// isValidEntry checks if a data entry is valid based on predefined criteria.
func isValidEntry(entry map[string]interface{}) bool {
	// Example validation: check if required fields are present
	requiredFields := []string{"timestamp", "value"}
	for _, field := range requiredFields {
		if _, exists := entry[field]; !exists {
			return false
		}
	}
	return true
}

// normalizeValues applies min-max scaling to normalize data values.
func normalizeValues(data []map[string]interface{}) []map[string]interface{} {
	var min, max float64
	min, max = findMinMax(data)

	for _, entry := range data {
		if value, exists := entry["value"].(float64); exists {
			entry["value"] = (value - min) / (max - min)
		}
	}
	return data
}

// findMinMax finds the minimum and maximum values in the data.
func findMinMax(data []map[string]interface{}) (float64, float64) {
	var min, max float64
	min, max = data[0]["value"].(float64), data[0]["value"].(float64)

	for _, entry := range data {
		if value, exists := entry["value"].(float64); exists {
			if value < min {
				min = value
			}
			if value > max {
				max = value
			}
		}
	}
	return min, max
}
