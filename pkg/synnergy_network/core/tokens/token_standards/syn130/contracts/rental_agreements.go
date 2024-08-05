package contracts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// RentalAgreement represents a smart contract for rental agreements.
type RentalAgreement struct {
	ID              string    `json:"id"`
	AssetID         string    `json:"asset_id"`
	Lessor          string    `json:"lessor"`
	Lessee          string    `json:"lessee"`
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	Terms           string    `json:"terms"`
	EncryptedTerms  string    `json:"encrypted_terms"`
	EncryptionKey   string    `json:"encryption_key"`
	Status          string    `json:"status"`
	PaymentSchedule string    `json:"payment_schedule"`
}

// NewRentalAgreement creates a new rental agreement.
func NewRentalAgreement(assetID, lessor, lessee, terms, paymentSchedule string, startDate, endDate time.Time) (*RentalAgreement, error) {
	if assetID == "" || lessor == "" || lessee == "" || terms == "" || paymentSchedule == "" {
		return nil, errors.New("missing required fields")
	}
	id := generateID()
	encryptionKey := generateEncryptionKey()
	encryptedTerms, err := encrypt(terms, encryptionKey)
	if err != nil {
		return nil, err
	}
	return &RentalAgreement{
		ID:              id,
		AssetID:         assetID,
		Lessor:          lessor,
		Lessee:          lessee,
		StartDate:       startDate,
		EndDate:         endDate,
		Terms:           terms,
		EncryptedTerms:  encryptedTerms,
		EncryptionKey:   encryptionKey,
		Status:          "active",
		PaymentSchedule: paymentSchedule,
	}, nil
}

// Terminate terminates the rental agreement.
func (ra *RentalAgreement) Terminate() {
	ra.Status = "terminated"
}

// Renew renews the rental agreement with new terms and dates.
func (ra *RentalAgreement) Renew(newTerms, newPaymentSchedule string, newStartDate, newEndDate time.Time) error {
	encryptionKey := generateEncryptionKey()
	encryptedTerms, err := encrypt(newTerms, encryptionKey)
	if err != nil {
		return err
	}
	ra.Terms = newTerms
	ra.EncryptedTerms = encryptedTerms
	ra.EncryptionKey = encryptionKey
	ra.StartDate = newStartDate
	ra.EndDate = newEndDate
	ra.PaymentSchedule = newPaymentSchedule
	ra.Status = "renewed"
	return nil
}

// VerifyTerms verifies the encrypted terms with the original terms.
func (ra *RentalAgreement) VerifyTerms() bool {
	decryptedTerms, err := decrypt(ra.EncryptedTerms, ra.EncryptionKey)
	if err != nil {
		return false
	}
	return ra.Terms == decryptedTerms
}

// Utility functions

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateEncryptionKey() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte("passphrase"), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(key)
}

func encrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
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

func decrypt(encryptedData, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
