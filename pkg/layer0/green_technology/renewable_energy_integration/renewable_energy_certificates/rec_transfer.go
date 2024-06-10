package renewable_energy_certificates

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/synthron_blockchain_final/pkg/layer0/blockchain"
	"golang.org/x/crypto/scrypt"
	"time"
)

// REC represents a Renewable Energy Certificate.
type REC struct {
	CertificateID   string `json:"certificate_id"`
	IssuerID        string `json:"issuer_id"`
	HolderID        string `json:"holder_id"`
	EnergyAmount    string `json:"energy_amount"`
	IssuanceDate    string `json:"issuance_date"`
	ExpirationDate  string `json:"expiration_date"`
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
func CreateREC(certificateID, issuerID, holderID, energyAmount, expirationDate, password string) error {
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

	rec := REC{
		CertificateID:   certificateID,
		IssuerID:        issuerID,
		HolderID:        holderID,
		EnergyAmount:    energyAmount,
		IssuanceDate:    time.Now().Format(time.RFC3339),
		ExpirationDate:  expirationDate,
		EncryptedEnergy: encryptedEnergy,
	}

	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	return blockchain.PutState(certificateID, recJSON)
}

// GetREC retrieves and decrypts a renewable energy certificate from the blockchain.
func GetREC(certificateID, password string) (*REC, error) {
	recJSON, err := blockchain.GetState(certificateID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from blockchain: %v", err)
	}
	if recJSON == nil {
		return nil, fmt.Errorf("the certificate %s does not exist", certificateID)
	}

	var rec REC
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
func UpdateREC(certificateID, issuerID, holderID, energyAmount, expirationDate, password string) error {
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

	rec := REC{
		CertificateID:   certificateID,
		IssuerID:        issuerID,
		HolderID:        holderID,
		EnergyAmount:    energyAmount,
		IssuanceDate:    time.Now().Format(time.RFC3339),
		ExpirationDate:  expirationDate,
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
	return UpdateREC(rec.CertificateID, rec.IssuerID, rec.HolderID, rec.EnergyAmount, rec.ExpirationDate, password)
}

// ListAllRECs lists all renewable energy certificates.
func ListAllRECs() ([]REC, error) {
	// Placeholder for a method to list all RECs.
	// This would typically involve querying the blockchain ledger for all REC records.
	// For now, we return an empty list.
	return []REC{}, nil
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

