package smart_contracts

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
	"golang.org/x/crypto/scrypt"
)

// EnergySource represents a renewable energy source with its details.
type EnergySource struct {
	SourceID          string `json:"source_id"`
	SourceType        string `json:"source_type"`
	Location          string `json:"location"`
	Capacity          string `json:"capacity"`
	GeneratedEnergy   string `json:"generated_energy"`
	RegistrationDate  string `json:"registration_date"`
	LastUpdatedDate   string `json:"last_updated_date"`
	EncryptedCapacity string `json:"encrypted_capacity"`
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

// RegisterEnergySource registers a new renewable energy source on the blockchain.
func RegisterEnergySource(sourceID, sourceType, location, capacity, password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedCapacity, err := EncryptData(capacity, key)
	if err != nil {
		return err
	}

	energySource := EnergySource{
		SourceID:          sourceID,
		SourceType:        sourceType,
		Location:          location,
		Capacity:          capacity,
		GeneratedEnergy:   "0",
		RegistrationDate:  time.Now().Format(time.RFC3339),
		LastUpdatedDate:   time.Now().Format(time.RFC3339),
		EncryptedCapacity: encryptedCapacity,
	}

	energySourceJSON, err := json.Marshal(energySource)
	if err != nil {
		return err
	}

	return blockchain.PutState(sourceID, energySourceJSON)
}

// GetEnergySource retrieves and decrypts a renewable energy source from the blockchain.
func GetEnergySource(sourceID, password string) (*EnergySource, error) {
	energySourceJSON, err := blockchain.GetState(sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if energySourceJSON == nil {
		return nil, fmt.Errorf("the source %s does not exist", sourceID)
	}

	var energySource EnergySource
	err = json.Unmarshal(energySourceJSON, &energySource)
	if err != nil {
		return nil, err
	}

	salt := []byte(energySource.SourceID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	capacity, err := DecryptData(energySource.EncryptedCapacity, key)
	if err != nil {
		return nil, err
	}

	energySource.Capacity = capacity
	return &energySource, nil
}

// UpdateEnergySource updates an existing renewable energy source on the blockchain.
func UpdateEnergySource(sourceID, sourceType, location, capacity, password string) error {
	exists, err := EnergySourceExists(sourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the source %s does not exist", sourceID)
	}

	salt := []byte(sourceID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedCapacity, err := EncryptData(capacity, key)
	if err != nil {
		return err
	}

	energySource := EnergySource{
		SourceID:          sourceID,
		SourceType:        sourceType,
		Location:          location,
		Capacity:          capacity,
		GeneratedEnergy:   "0", // Reset generated energy upon update
		RegistrationDate:  time.Now().Format(time.RFC3339), // Update registration date
		LastUpdatedDate:   time.Now().Format(time.RFC3339),
		EncryptedCapacity: encryptedCapacity,
	}

	energySourceJSON, err := json.Marshal(energySource)
	if err != nil {
		return err
	}

	return blockchain.PutState(sourceID, energySourceJSON)
}

// DeleteEnergySource deletes a renewable energy source from the blockchain.
func DeleteEnergySource(sourceID string) error {
	exists, err := EnergySourceExists(sourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the source %s does not exist", sourceID)
	}

	return blockchain.DelState(sourceID)
}

// EnergySourceExists checks if a renewable energy source exists on the blockchain.
func EnergySourceExists(sourceID string) (bool, error) {
	energySourceJSON, err := blockchain.GetState(sourceID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return energySourceJSON != nil, nil
}

// TransferEnergySource transfers the ownership of a renewable energy source to a new owner.
func TransferEnergySource(sourceID, newOwnerID, password string) error {
	energySource, err := GetEnergySource(sourceID, password)
	if err != nil {
		return err
	}

	energySource.SourceType = newOwnerID
	return UpdateEnergySource(energySource.SourceID, energySource.SourceType, energySource.Location, energySource.Capacity, password)
}

// ListAllEnergySources lists all renewable energy sources.
func ListAllEnergySources() ([]EnergySource, error) {
	// Placeholder for a method to list all energy sources.
	// This would typically involve querying the blockchain ledger for all energy source records.
	// For now, we return an empty list.
	return []EnergySource{}, nil
}

// TransferRequest represents a request to transfer a renewable energy source.
type TransferRequest struct {
	SourceID   string `json:"source_id"`
	NewOwnerID string `json:"new_owner_id"`
	Password   string `json:"password"`
}

// HandleTransferRequest handles the transfer request for a renewable energy source.
func HandleTransferRequest(request TransferRequest) error {
	return TransferEnergySource(request.SourceID, request.NewOwnerID, request.Password)
}

// GenerateTransferRequest generates a transfer request for a renewable energy source.
func GenerateTransferRequest(sourceID, newOwnerID, password string) TransferRequest {
	return TransferRequest{
		SourceID:   sourceID,
		NewOwnerID: newOwnerID,
		Password:   password,
	}
}
