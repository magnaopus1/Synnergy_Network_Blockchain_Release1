package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// TicketTransfer handles the transfer of event tickets
type TicketTransfer struct {
	aesKey []byte
	salt   []byte
}

// NewTicketTransfer creates a new instance of TicketTransfer
func NewTicketTransfer(passphrase string) (*TicketTransfer, error) {
	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &TicketTransfer{
		aesKey: key,
		salt:   salt,
	}, nil
}

// TransferData represents the data involved in a ticket transfer
type TransferData struct {
	EventID      string    `json:"event_id"`
	TicketID     string    `json:"ticket_id"`
	FromOwnerID  string    `json:"from_owner_id"`
	ToOwnerID    string    `json:"to_owner_id"`
	TransferDate time.Time `json:"transfer_date"`
	TransactionID string   `json:"transaction_id"`
	Signature    string    `json:"signature"`
}

// InitiateTransfer initiates a secure transfer of tickets
func (tt *TicketTransfer) InitiateTransfer(transferData TransferData) (string, error) {
	data, err := json.Marshal(transferData)
	if err != nil {
		return "", err
	}

	encryptedData, err := tt.encrypt(data)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// ValidateTransfer validates a secure transfer of tickets
func (tt *TicketTransfer) ValidateTransfer(encryptedTransfer string) (*TransferData, error) {
	decryptedData, err := tt.decrypt(encryptedTransfer)
	if err != nil {
		return nil, err
	}

	var transferData TransferData
	err = json.Unmarshal(decryptedData, &transferData)
	if err != nil {
		return nil, err
	}

	// Verify the transfer data (e.g., check signatures, ensure transfer date is valid)
	if transferData.TransferDate.After(time.Now()) {
		return nil, errors.New("transfer date is in the future")
	}

	return &transferData, nil
}

// encrypt encrypts the data using AES-GCM
func (tt *TicketTransfer) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(tt.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the data using AES-GCM
func (tt *TicketTransfer) decrypt(data string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(tt.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(decodedData) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedData[:gcm.NonceSize()], decodedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

