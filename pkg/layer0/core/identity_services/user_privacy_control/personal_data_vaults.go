package userprivacycontrol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"synthron_blockchain_final/pkg/layer0/core/blockchain"
)

// IPersonalDataVault defines the interface for personal data vault functionalities.
type IPersonalDataVault interface {
	StoreData(userID string, data []byte) error
	RetrieveData(userID string, requesterID string) ([]byte, error)
	UpdateData(userID string, data []byte) error
	DeleteData(userID string) error
}

// PersonalDataVault implements data storage with privacy and security.
type PersonalDataVault struct {
	blockchain  blockchain.Interface
	encryptionKey *rsa.PrivateKey
}

// NewPersonalDataVault creates a new instance of PersonalDataVault with necessary initializations.
func NewPersonalDataVault(bc blockchain.Interface, key *rsa.PrivateKey) *PersonalDataVault {
	return &PersonalDataVault{
		blockchain:    bc,
		encryptionKey: key,
	}
}

// encryptData encrypts data using AES encryption.
func (pdv *PersonalDataVault) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(pdv.encryptionKey.PublicKey.N.Bytes()[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES encryption.
func (pdv *PersonalDataVault) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(pdv.encryptionKey.PublicKey.N.Bytes()[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// StoreData securely stores encrypted data in the blockchain.
func (pdv *PersonalDataVault) StoreData(userID string, data []byte) error {
	encryptedData, err := pdv.encryptData(data)
	if err != nil {
		return err
	}
	return pdv.blockchain.StoreData(userID, encryptedData)
}

// RetrieveData retrieves and decrypts user data from the blockchain.
func (pdv *PersonalDataVault) RetrieveData(userID string, requesterID string) ([]byte, error) {
	encryptedData, err := pdv.blockchain.RetrieveData(userID)
	if err != nil {
		return nil, err
	}
	if !pdv.authorizeAccess(userID, requesterID) {
		return nil, errors.New("unauthorized access")
	}
	return pdv.decryptData(encryptedData.([]byte))
}

// UpdateData updates existing encrypted user data in the blockchain.
func (pdv *PersonalDataVault) UpdateData(userID string, data []byte) error {
	encryptedData, err := pdv.encryptData(data)
	if err != nil {
		return err
	}
	return pdv.blockchain.UpdateData(userID, encryptedData)
}

// DeleteData removes user data from the blockchain.
func (pdv *PersonalDataVault) DeleteData(userID string) error {
	return pdv.blockchain.DeleteData(userID)
}

// authorizeAccess checks if the requester is authorized to access the data.
func (pdv *PersonalDataVault) authorizeAccess(userID string, requesterID string) bool {
	// This function should integrate with the consent management system to check for valid access.
	return true // Placeholder for demonstration.
}

// GenerateSHA256 generates a SHA-256 hash of the data.
func GenerateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Implementation of additional functionalities such as data integrity checks, compliance adherence,
// and conditional access based on real-time consent updates would also be implemented here.
