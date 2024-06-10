package smart_contracts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/synthron_blockchain_final/pkg/layer0/green_technology/energy_usage_monitoring"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// EnergyDataSecurity represents the structure for encrypted energy data.
type EnergyDataSecurity struct {
	NodeID      string `json:"node_id"`
	Timestamp   string `json:"timestamp"`
	Usage       string `json:"usage"`
	Temperature string `json:"temperature"`
	Humidity    string `json:"humidity"`
}

// SmartContract provides functions for managing energy data securely.
type SmartContract struct {
	contractapi.Contract
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

// AddSecureEnergyData adds new encrypted energy data to the ledger.
func (s *SmartContract) AddSecureEnergyData(ctx contractapi.TransactionContextInterface, nodeID, timestamp, usage, temperature, humidity, password string) error {
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

	data := EnergyDataSecurity{
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

	return ctx.GetStub().PutState(nodeID, dataJSON)
}

// GetSecureEnergyData retrieves and decrypts energy data from the ledger.
func (s *SmartContract) GetSecureEnergyData(ctx contractapi.TransactionContextInterface, nodeID, password string) (*EnergyDataSecurity, error) {
	dataJSON, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if dataJSON == nil {
		return nil, fmt.Errorf("the data %s does not exist", nodeID)
	}

	var data EnergyDataSecurity
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

// UpdateSecureEnergyData updates an existing encrypted energy data record in the ledger.
func (s *SmartContract) UpdateSecureEnergyData(ctx contractapi.TransactionContextInterface, nodeID, timestamp, usage, temperature, humidity, password string) error {
	exists, err := s.EnergyDataExists(ctx, nodeID)
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

	data := EnergyDataSecurity{
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

	return ctx.GetStub().PutState(nodeID, dataJSON)
}

// DeleteSecureEnergyData deletes an encrypted energy data record from the ledger.
func (s *SmartContract) DeleteSecureEnergyData(ctx contractapi.TransactionContextInterface, nodeID string) error {
	exists, err := s.EnergyDataExists(ctx, nodeID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the energy data %s does not exist", nodeID)
	}

	return ctx.GetStub().DelState(nodeID)
}

// EnergyDataExists checks if an energy data record exists in the ledger.
func (s *SmartContract) EnergyDataExists(ctx contractapi.TransactionContextInterface, nodeID string) (bool, error) {
	dataJSON, err := ctx.GetStub().GetState(nodeID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return dataJSON != nil, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating energy data security chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting energy data security chaincode: %v", err)
	}
}
