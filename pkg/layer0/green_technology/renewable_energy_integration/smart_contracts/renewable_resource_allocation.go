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

// RenewableResource represents a renewable resource with its details.
type RenewableResource struct {
	ResourceID        string `json:"resource_id"`
	ResourceType      string `json:"resource_type"`
	Location          string `json:"location"`
	Capacity          string `json:"capacity"`
	AllocatedEnergy   string `json:"allocated_energy"`
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

// RegisterRenewableResource registers a new renewable resource on the blockchain.
func RegisterRenewableResource(resourceID, resourceType, location, capacity, password string) error {
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

	resource := RenewableResource{
		ResourceID:        resourceID,
		ResourceType:      resourceType,
		Location:          location,
		Capacity:          capacity,
		AllocatedEnergy:   "0",
		RegistrationDate:  time.Now().Format(time.RFC3339),
		LastUpdatedDate:   time.Now().Format(time.RFC3339),
		EncryptedCapacity: encryptedCapacity,
	}

	resourceJSON, err := json.Marshal(resource)
	if err != nil {
		return err
	}

	return blockchain.PutState(resourceID, resourceJSON)
}

// GetRenewableResource retrieves and decrypts a renewable resource from the blockchain.
func GetRenewableResource(resourceID, password string) (*RenewableResource, error) {
	resourceJSON, err := blockchain.GetState(resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if resourceJSON == nil {
		return nil, fmt.Errorf("the resource %s does not exist", resourceID)
	}

	var resource RenewableResource
	err = json.Unmarshal(resourceJSON, &resource)
	if err != nil {
		return nil, err
	}

	salt := []byte(resource.ResourceID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	capacity, err := DecryptData(resource.EncryptedCapacity, key)
	if err != nil {
		return nil, err
	}

	resource.Capacity = capacity
	return &resource, nil
}

// UpdateRenewableResource updates an existing renewable resource on the blockchain.
func UpdateRenewableResource(resourceID, resourceType, location, capacity, password string) error {
	exists, err := RenewableResourceExists(resourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the resource %s does not exist", resourceID)
	}

	salt := []byte(resourceID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedCapacity, err := EncryptData(capacity, key)
	if err != nil {
		return err
	}

	resource := RenewableResource{
		ResourceID:        resourceID,
		ResourceType:      resourceType,
		Location:          location,
		Capacity:          capacity,
		AllocatedEnergy:   "0", // Reset allocated energy upon update
		RegistrationDate:  time.Now().Format(time.RFC3339), // Update registration date
		LastUpdatedDate:   time.Now().Format(time.RFC3339),
		EncryptedCapacity: encryptedCapacity,
	}

	resourceJSON, err := json.Marshal(resource)
	if err != nil {
		return err
	}

	return blockchain.PutState(resourceID, resourceJSON)
}

// DeleteRenewableResource deletes a renewable resource from the blockchain.
func DeleteRenewableResource(resourceID string) error {
	exists, err := RenewableResourceExists(resourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the resource %s does not exist", resourceID)
	}

	return blockchain.DelState(resourceID)
}

// RenewableResourceExists checks if a renewable resource exists on the blockchain.
func RenewableResourceExists(resourceID string) (bool, error) {
	resourceJSON, err := blockchain.GetState(resourceID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return resourceJSON != nil, nil
}

// AllocateEnergy allocates energy from a renewable resource to a user.
func AllocateEnergy(resourceID, userID, energyAmount, password string) error {
	resource, err := GetRenewableResource(resourceID, password)
	if err != nil {
		return err
	}

	// Ensure there is enough capacity to allocate
	if resource.AllocatedEnergy+energyAmount > resource.Capacity {
		return fmt.Errorf("insufficient capacity in resource %s to allocate %s energy", resourceID, energyAmount)
	}

	// Update allocated energy
	resource.AllocatedEnergy += energyAmount
	resource.LastUpdatedDate = time.Now().Format(time.RFC3339)

	return UpdateRenewableResource(resource.ResourceID, resource.ResourceType, resource.Location, resource.Capacity, password)
}

// TransferRenewableResource transfers the ownership of a renewable resource to a new owner.
func TransferRenewableResource(resourceID, newOwnerID, password string) error {
	resource, err := GetRenewableResource(resourceID, password)
	if err != nil {
		return err
	}

	resource.ResourceType = newOwnerID
	return UpdateRenewableResource(resource.ResourceID, resource.ResourceType, resource.Location, resource.Capacity, password)
}

// ListAllRenewableResources lists all renewable resources.
func ListAllRenewableResources() ([]RenewableResource, error) {
	// Placeholder for a method to list all renewable resources.
	// This would typically involve querying the blockchain ledger for all renewable resource records.
	// For now, we return an empty list.
	return []RenewableResource{}, nil
}

// TransferRequest represents a request to transfer a renewable resource.
type TransferRequest struct {
	ResourceID string `json:"resource_id"`
	NewOwnerID string `json:"new_owner_id"`
	Password   string `json:"password"`
}

// HandleTransferRequest handles the transfer request for a renewable resource.
func HandleTransferRequest(request TransferRequest) error {
	return TransferRenewableResource(request.ResourceID, request.NewOwnerID, request.Password)
}

// GenerateTransferRequest generates a transfer request for a renewable resource.
func GenerateTransferRequest(resourceID, newOwnerID, password string) TransferRequest {
	return TransferRequest{
		ResourceID: resourceID,
		NewOwnerID: newOwnerID,
		Password:   password,
	}
}
