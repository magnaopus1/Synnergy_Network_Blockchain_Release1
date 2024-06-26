package energy_usage_monitoring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/energy_usage_monitoring/models"
	"golang.org/x/crypto/scrypt"
)

// EnergyUsageData represents the structure for energy usage data.
type EnergyUsageData struct {
	NodeID      string `json:"node_id"`
	Timestamp   string `json:"timestamp"`
	Usage       string `json:"usage"`
	Temperature string `json:"temperature"`
	Humidity    string `json:"humidity"`
}

// GenerateSalt generates a new salt for encryption.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey derives a key from a password and a salt using scrypt.
func DeriveKey(password string, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// EncryptData encrypts the given data using AES with the derived key.
func EncryptData(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given encrypted data using AES with the derived key.
func DecryptData(encryptedData string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AddSecureEnergyData adds new encrypted energy data to the blockchain.
func AddSecureEnergyData(nodeID, timestamp, usage, temperature, humidity, password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedUsage, err := EncryptData(usage, key)
	if err != nil {
		return err
	}

	encryptedTemperature, err := EncryptData(temperature, key)
	if err != nil {
		return err
	}

	encryptedHumidity, err := EncryptData(humidity, key)
	if err != nil {
		return err
	}

	data := EnergyUsageData{
		NodeID:      nodeID,
		Timestamp:   timestamp,
		Usage:       encryptedUsage,
		Temperature: encryptedTemperature,
		Humidity:    encryptedHumidity,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return blockchain.PutState(nodeID, dataJSON)
}

// GetSecureEnergyData retrieves and decrypts energy data from the blockchain.
func GetSecureEnergyData(nodeID, password string) (*EnergyUsageData, error) {
	dataJSON, err := blockchain.GetState(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if dataJSON == nil {
		return nil, fmt.Errorf("the data %s does not exist", nodeID)
	}

	var data EnergyUsageData
	err = json.Unmarshal(dataJSON, &data)
	if err != nil {
		return nil, err
	}

	salt := []byte(data.NodeID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	usage, err := DecryptData(data.Usage, key)
	if err != nil {
		return nil, err
	}

	temperature, err := DecryptData(data.Temperature, key)
	if err != nil {
		return nil, err
	}

	humidity, err := DecryptData(data.Humidity, key)
	if err != nil {
		return nil, err
	}

	data.Usage = usage
	data.Temperature = temperature
	data.Humidity = humidity

	return &data, nil
}

// UpdateSecureEnergyData updates an existing encrypted energy data record in the blockchain.
func UpdateSecureEnergyData(nodeID, timestamp, usage, temperature, humidity, password string) error {
	exists, err := EnergyDataExists(nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the energy data %s does not exist", nodeID)
	}

	salt := []byte(nodeID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedUsage, err := EncryptData(usage, key)
	if err != nil {
		return err
	}

	encryptedTemperature, err := EncryptData(temperature, key)
	if err != nil {
		return err
	}

	encryptedHumidity, err := EncryptData(humidity, key)
	if err != nil {
		return err
	}

	data := EnergyUsageData{
		NodeID:      nodeID,
		Timestamp:   timestamp,
		Usage:       encryptedUsage,
		Temperature: encryptedTemperature,
		Humidity:    encryptedHumidity,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return blockchain.PutState(nodeID, dataJSON)
}

// DeleteSecureEnergyData deletes an encrypted energy data record from the blockchain.
func DeleteSecureEnergyData(nodeID string) error {
	exists, err := EnergyDataExists(nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the energy data %s does not exist", nodeID)
	}

	return blockchain.DelState(nodeID)
}

// EnergyDataExists checks if an energy data record exists in the blockchain.
func EnergyDataExists(nodeID string) (bool, error) {
	dataJSON, err := blockchain.GetState(nodeID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return dataJSON != nil, nil
}

// MonitorEnergyUsage continuously monitors energy usage and stores the data securely.
func MonitorEnergyUsage(nodeID, password string, interval time.Duration) {
	for range time.Tick(interval) {
		// Simulate gathering energy usage data
		timestamp := time.Now().Format(time.RFC3339)
		usage := fmt.Sprintf("%f", 123.45)      // Replace with actual data collection
		temperature := fmt.Sprintf("%f", 22.5)  // Replace with actual data collection
		humidity := fmt.Sprintf("%f", 45.6)     // Replace with actual data collection

		err := AddSecureEnergyData(nodeID, timestamp, usage, temperature, humidity, password)
		if err != nil {
			fmt.Printf("Error adding secure energy data: %v\n", err)
		}
	}
}

// PredictiveEnergyManagement uses historical data to predict future energy usage.
func PredictiveEnergyManagement(nodeID string) (string, error) {
	// Placeholder for implementing machine learning algorithms for predictive analysis
	// This would typically involve analyzing historical data and making predictions
	// about future energy usage patterns.
	//
	// For now, we return a static prediction.
	prediction := "Future energy usage is predicted to be within safe limits."
	return prediction, nil
}
