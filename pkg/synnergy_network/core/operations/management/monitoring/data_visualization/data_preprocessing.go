package data_visualization

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// DataPreprocessor handles data preprocessing tasks for data visualization and analysis.
type DataPreprocessor struct {
	logger *zap.Logger
}

// NewDataPreprocessor creates a new DataPreprocessor.
func NewDataPreprocessor(logger *zap.Logger) *DataPreprocessor {
	return &DataPreprocessor{
		logger: logger,
	}
}

// PreprocessData processes raw data based on provided settings.
func (dp *DataPreprocessor) PreprocessData(rawData []byte, settings map[string]interface{}) ([]byte, error) {
	dp.logger.Info("Starting data preprocessing")
	processedData := rawData

	// Example preprocessing steps
	if val, ok := settings["removeDuplicates"].(bool); ok && val {
		processedData = dp.removeDuplicates(processedData)
	}
	if val, ok := settings["normalize"].(bool); ok && val {
		processedData = dp.normalizeData(processedData)
	}
	if val, ok := settings["encrypt"].(bool); ok && val {
		passphrase := settings["passphrase"].(string)
		encData, err := dp.encryptData(processedData, passphrase)
		if err != nil {
			return nil, err
		}
		processedData = encData
	}

	dp.logger.Info("Data preprocessing completed")
	return processedData, nil
}

// removeDuplicates removes duplicate entries from the data.
func (dp *DataPreprocessor) removeDuplicates(data []byte) []byte {
	dp.logger.Info("Removing duplicates from data")
	// Implement logic to remove duplicates
	return data
}

// normalizeData normalizes the data.
func (dp *DataPreprocessor) normalizeData(data []byte) []byte {
	dp.logger.Info("Normalizing data")
	// Implement logic to normalize data
	return data
}

// encryptData encrypts the data using AES encryption with a passphrase.
func (dp *DataPreprocessor) encryptData(data []byte, passphrase string) ([]byte, error) {
	dp.logger.Info("Encrypting data")
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// decryptData decrypts the data using AES encryption with a passphrase.
func (dp *DataPreprocessor) decryptData(encryptedData []byte, passphrase string) ([]byte, error) {
	dp.logger.Info("Decrypting data")
	if len(encryptedData) < 16 {
		return nil, errors.New("invalid data")
	}

	salt := encryptedData[:16]
	encryptedData = encryptedData[16:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("invalid data")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ConvertCSVToJSON converts CSV data to JSON format.
func (dp *DataPreprocessor) ConvertCSVToJSON(csvData []byte) ([]byte, error) {
	dp.logger.Info("Converting CSV data to JSON format")
	r := csv.NewReader(strings.NewReader(string(csvData)))
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) < 1 {
		return nil, errors.New("no data found")
	}

	headers := records[0]
	var result []map[string]string
	for _, row := range records[1:] {
		record := make(map[string]string)
		for i, value := range row {
			record[headers[i]] = value
		}
		result = append(result, record)
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// SaveDataToFile saves data to a specified file.
func (dp *DataPreprocessor) SaveDataToFile(data []byte, filename string) error {
	dp.logger.Info("Saving data to file", zap.String("filename", filename))
	return os.WriteFile(filename, data, 0644)
}

// LoadDataFromFile loads data from a specified file.
func (dp *DataPreprocessor) LoadDataFromFile(filename string) ([]byte, error) {
	dp.logger.Info("Loading data from file", zap.String("filename", filename))
	return os.ReadFile(filename)
}

// ValidateDataFormat validates the format of the data based on predefined rules.
func (dp *DataPreprocessor) ValidateDataFormat(data []byte, rules map[string]interface{}) (bool, error) {
	dp.logger.Info("Validating data format")
	// Implement validation logic based on rules
	return true, nil
}

// ParseData parses data based on a specific format (e.g., CSV, JSON).
func (dp *DataPreprocessor) ParseData(data []byte, format string) (interface{}, error) {
	dp.logger.Info("Parsing data", zap.String("format", format))
	switch format {
	case "csv":
		return dp.parseCSV(data)
	case "json":
		return dp.parseJSON(data)
	default:
		return nil, errors.New("unsupported format")
	}
}

func (dp *DataPreprocessor) parseCSV(data []byte) ([][]string, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	return r.ReadAll()
}

func (dp *DataPreprocessor) parseJSON(data []byte) (interface{}, error) {
	var result interface{}
	err := json.Unmarshal(data, &result)
	return result, err
}

// GenerateSummaryStatistics generates summary statistics for numerical data.
func (dp *DataPreprocessor) GenerateSummaryStatistics(data []byte) (map[string]float64, error) {
	dp.logger.Info("Generating summary statistics")
	var records []map[string]string
	err := json.Unmarshal(data, &records)
	if err != nil {
		return nil, err
	}

	stats := make(map[string]float64)
	for _, record := range records {
		for key, value := range record {
			if num, err := strconv.ParseFloat(value, 64); err == nil {
				stats[key+"_sum"] += num
				stats[key+"_count"]++
			}
		}
	}

	for key, value := range stats {
		if strings.HasSuffix(key, "_sum") {
			countKey := strings.TrimSuffix(key, "_sum") + "_count"
			stats[strings.TrimSuffix(key, "_sum")+"_mean"] = value / stats[countKey]
		}
	}

	return stats, nil
}

