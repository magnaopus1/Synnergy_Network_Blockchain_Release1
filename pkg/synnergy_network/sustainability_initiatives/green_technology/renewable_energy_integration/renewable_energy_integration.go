package renewable_energy_integration

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

// RenewableEnergyCertificate represents a renewable energy certificate (REC).
type RenewableEnergyCertificate struct {
	CertificateID   string `json:"certificate_id"`
	SourceID        string `json:"source_id"`
	EnergyAmount    string `json:"energy_amount"`
	IssuanceDate    string `json:"issuance_date"`
	ExpirationDate  string `json:"expiration_date"`
	HolderID        string `json:"holder_id"`
	EncryptedEnergy string `json:"encrypted_energy"`
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

// CreateREC creates a new renewable energy certificate on the blockchain.
func CreateREC(certificateID, sourceID, energyAmount, expirationDate, holderID, password string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedEnergy, err := EncryptData(energyAmount, key)
	if err != nil {
		return err
	}

	rec := RenewableEnergyCertificate{
		CertificateID:   certificateID,
		SourceID:        sourceID,
		EnergyAmount:    energyAmount,
		IssuanceDate:    time.Now().Format(time.RFC3339),
		ExpirationDate:  expirationDate,
		HolderID:        holderID,
		EncryptedEnergy: encryptedEnergy,
	}

	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	return blockchain.PutState(certificateID, recJSON)
}

// GetREC retrieves and decrypts a renewable energy certificate from the blockchain.
func GetREC(certificateID, password string) (*RenewableEnergyCertificate, error) {
	recJSON, err := blockchain.GetState(certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if recJSON == nil {
		return nil, fmt.Errorf("the certificate %s does not exist", certificateID)
	}

	var rec RenewableEnergyCertificate
	err = json.Unmarshal(recJSON, &rec)
	if err != nil {
		return nil, err
	}

	salt := []byte(rec.CertificateID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	energyAmount, err := DecryptData(rec.EncryptedEnergy, key)
	if err != nil {
		return nil, err
	}

	rec.EnergyAmount = energyAmount
	return &rec, nil
}

// UpdateREC updates an existing renewable energy certificate on the blockchain.
func UpdateREC(certificateID, sourceID, energyAmount, expirationDate, holderID, password string) error {
	exists, err := RECExists(certificateID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the certificate %s does not exist", certificateID)
	}

	salt := []byte(certificateID)
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}

	encryptedEnergy, err := EncryptData(energyAmount, key)
	if err != nil {
		return err
	}

	rec := RenewableEnergyCertificate{
		CertificateID:   certificateID,
		SourceID:        sourceID,
		EnergyAmount:    energyAmount,
		IssuanceDate:    time.Now().Format(time.RFC3339),
		ExpirationDate:  expirationDate,
		HolderID:        holderID,
		EncryptedEnergy: encryptedEnergy,
	}

	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	return blockchain.PutState(certificateID, recJSON)
}

// DeleteREC deletes a renewable energy certificate from the blockchain.
func DeleteREC(certificateID string) error {
	exists, err := RECExists(certificateID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the certificate %s does not exist", certificateID)
	}

	return blockchain.DelState(certificateID)
}

// RECExists checks if a renewable energy certificate exists on the blockchain.
func RECExists(certificateID string) (bool, error) {
	recJSON, err := blockchain.GetState(certificateID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return recJSON != nil, nil
}

// TransferREC transfers a renewable energy certificate to a new holder.
func TransferREC(certificateID, newHolderID, password string) error {
	rec, err := GetREC(certificateID, password)
	if err != nil {
		return err
	}

	rec.HolderID = newHolderID
	return UpdateREC(rec.CertificateID, rec.SourceID, rec.EnergyAmount, rec.ExpirationDate, rec.HolderID, password)
}

// ListAllRECs lists all renewable energy certificates.
func ListAllRECs() ([]RenewableEnergyCertificate, error) {
	// Placeholder for a method to list all RECs.
	// This would typically involve querying the blockchain ledger for all REC records.
	// For now, we return an empty list.
	return []RenewableEnergyCertificate{}, nil
}

// TransferRequest represents a request to transfer a renewable energy certificate.
type TransferRequest struct {
	CertificateID string `json:"certificate_id"`
	NewHolderID   string `json:"new_holder_id"`
	Password      string `json:"password"`
}

// HandleTransferRequest handles the transfer request for a renewable energy certificate.
func HandleTransferRequest(request TransferRequest) error {
	return TransferREC(request.CertificateID, request.NewHolderID, request.Password)
}

// GenerateTransferRequest generates a transfer request for a renewable energy certificate.
func GenerateTransferRequest(certificateID, newHolderID, password string) TransferRequest {
	return TransferRequest{
		CertificateID: certificateID,
		NewHolderID:   newHolderID,
		Password:      password,
	}
}

// RenewableEnergySource represents a renewable energy source.
type RenewableEnergySource struct {
	SourceID         string `json:"source_id"`
	SourceType       string `json:"source_type"`
	Location         string `json:"location"`
	Capacity         string `json:"capacity"`
	GeneratedEnergy  string `json:"generated_energy"`
	RegistrationDate string `json:"registration_date"`
	LastUpdatedDate  string `json:"last_updated_date"`
}

// RegisterRenewableEnergySource registers a new renewable energy source on the blockchain.
func RegisterRenewableEnergySource(sourceID, sourceType, location, capacity string) error {
	source := RenewableEnergySource{
		SourceID:         sourceID,
		SourceType:       sourceType,
		Location:         location,
		Capacity:         capacity,
		GeneratedEnergy:  "0",
		RegistrationDate: time.Now().Format(time.RFC3339),
		LastUpdatedDate:  time.Now().Format(time.RFC3339),
	}

	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return err
	}

	return blockchain.PutState(sourceID, sourceJSON)
}

// GetRenewableEnergySource retrieves a renewable energy source from the blockchain.
func GetRenewableEnergySource(sourceID string) (*RenewableEnergySource, error) {
	sourceJSON, err := blockchain.GetState(sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if sourceJSON == nil {
		return nil, fmt.Errorf("the source %s does not exist", sourceID)
	}

	var source RenewableEnergySource
	err = json.Unmarshal(sourceJSON, &source)
	if err != nil {
		return nil, err
	}

	return &source, nil
}

// UpdateRenewableEnergySource updates an existing renewable energy source on the blockchain.
func UpdateRenewableEnergySource(sourceID, sourceType, location, capacity string) error {
	exists, err := RenewableEnergySourceExists(sourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the source %s does not exist", sourceID)
	}

	source := RenewableEnergySource{
		SourceID:         sourceID,
		SourceType:       sourceType,
		Location:         location,
		Capacity:         capacity,
		GeneratedEnergy:  "0", // Reset generated energy upon update
		RegistrationDate: time.Now().Format(time.RFC3339), // Update registration date
		LastUpdatedDate:  time.Now().Format(time.RFC3339),
	}

	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return err
	}

	return blockchain.PutState(sourceID, sourceJSON)
}

// DeleteRenewableEnergySource deletes a renewable energy source from the blockchain.
func DeleteRenewableEnergySource(sourceID string) error {
	exists, err := RenewableEnergySourceExists(sourceID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("the source %s does not exist", sourceID)
	}

	return blockchain.DelState(sourceID)
}

// RenewableEnergySourceExists checks if a renewable energy source exists on the blockchain.
func RenewableEnergySourceExists(sourceID string) (bool, error) {
	sourceJSON, err := blockchain.GetState(sourceID)
	if err != nil {
		return false, fmt.Errorf("failed to read from blockchain: %v", err)
	}

	return sourceJSON != nil, nil
}

// AllocateEnergy allocates energy from a renewable energy source to a user.
func AllocateEnergy(sourceID, userID, energyAmount string) error {
	source, err := GetRenewableEnergySource(sourceID)
	if err != nil {
		return err
	}

	// Ensure there is enough capacity to allocate
	if source.GeneratedEnergy+energyAmount > source.Capacity {
		return fmt.Errorf("insufficient capacity in source %s to allocate %s energy", sourceID, energyAmount)
	}

	// Update generated energy
	source.GeneratedEnergy += energyAmount
	source.LastUpdatedDate = time.Now().Format(time.RFC3339)

	return UpdateRenewableEnergySource(source.SourceID, source.SourceType, source.Location, source.Capacity)
}

// ListAllRenewableEnergySources lists all renewable energy sources.
func ListAllRenewableEnergySources() ([]RenewableEnergySource, error) {
	// Placeholder for a method to list all renewable energy sources.
	// This would typically involve querying the blockchain ledger for all renewable energy source records.
	// For now, we return an empty list.
	return []RenewableEnergySource{}, nil
}

// TransferRenewableEnergySource transfers the ownership of a renewable energy source to a new owner.
func TransferRenewableEnergySource(sourceID, newOwnerID string) error {
	source, err := GetRenewableEnergySource(sourceID)
	if err != nil {
		return err
	}

	source.SourceType = newOwnerID
	return UpdateRenewableEnergySource(source.SourceID, source.SourceType, source.Location, source.Capacity)
}

// TransferSourceRequest represents a request to transfer a renewable energy source.
type TransferSourceRequest struct {
	SourceID   string `json:"source_id"`
	NewOwnerID string `json:"new_owner_id"`
}

// HandleSourceTransferRequest handles the transfer request for a renewable energy source.
func HandleSourceTransferRequest(request TransferSourceRequest) error {
	return TransferRenewableEnergySource(request.SourceID, request.NewOwnerID)
}

// GenerateSourceTransferRequest generates a transfer request for a renewable energy source.
func GenerateSourceTransferRequest(sourceID, newOwnerID string) TransferSourceRequest {
	return TransferSourceRequest{
		SourceID:   sourceID,
		NewOwnerID: newOwnerID,
	}
}
