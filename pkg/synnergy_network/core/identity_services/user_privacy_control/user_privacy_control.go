package userprivacycontrol

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"synthron_blockchain_final/pkg/layer0/core/identity_services/blockchain"
)

// UserPrivacyControl manages user data privacy and consent within the blockchain network.
type UserPrivacyControl struct {
	Blockchain blockchain.Interface
}

// NewUserPrivacyControl creates a new instance of UserPrivacyControl.
func NewUserPrivacyControl(blockchain blockchain.Interface) *UserPrivacyControl {
	return &UserPrivacyControl{
		Blockchain: blockchain,
	}
}

// ConsentRecord encapsulates a user's consent regarding their personal data.
type ConsentRecord struct {
	UserID        string
	DataCategory  string
	ConsentGiven  bool
	ValidUntil    int64
	TransactionID string
}

// EncryptUserData encrypts user data using RSA encryption before storing it on the blockchain.
func (upc *UserPrivacyControl) EncryptUserData(userID string, data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, data)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

// DecryptUserData decrypts the user data retrieved from the blockchain.
func (upc *UserPrivacyControl) DecryptUserData(userID string, encryptedData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

// RecordConsent logs the user's consent for data use on the blockchain.
func (upc *UserPrivacyControl) RecordConsent(consent ConsentRecord) error {
	if consent.ConsentGiven {
		return upc.Blockchain.WriteConsentRecord(consent)
	}
	return errors.New("consent not given by user")
}

// CheckConsent verifies if the consent for a specific data category is still valid.
func (upc *UserPrivacyControl) CheckConsent(userID string, dataCategory string) (bool, error) {
	consent, err := upc.Blockchain.ReadConsentRecord(userID, dataCategory)
	if err != nil {
		return false, err
	}
	return consent.ConsentGiven && consent.ValidUntil > GetCurrentTimestamp(), nil
}

// RevokeConsent allows a user to revoke any previously given consent.
func (upc *UserPrivacyControl) RevokeConsent(userID string, dataCategory string) error {
	return upc.Blockchain.UpdateConsentRecord(userID, dataCategory, false)
}

// GetCurrentTimestamp returns the current UNIX timestamp.
func GetCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// ConfigurePrivacySettings allows users to configure their privacy settings through a user-friendly interface.
func (upc *UserPrivacyControl) ConfigurePrivacySettings(userID string, settings map[string]bool) error {
	for category, consent := range settings {
		err := upc.RecordConsent(ConsentRecord{
			UserID:       userID,
			DataCategory: category,
			ConsentGiven: consent,
			ValidUntil:   GetCurrentTimestamp() + 31536000, // 1 year from now
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Data masking and additional privacy control functions would be implemented below,
// ensuring all user data interactions on the network adhere to the highest standards of data protection.
