package interoperability

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// CrossChainDAppEco represents a decentralized application ecosystem for cross-chain interoperability
type CrossChainDAppEco struct {
	AppID          string
	ChainID        string
	ParticipantIDs []string
	ContractData   []byte
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	DAppActive   = "ACTIVE"
	DAppInactive = "INACTIVE"
	DAppClosed   = "CLOSED"
)

// NewCrossChainDAppEco initializes a new CrossChainDAppEco instance
func NewCrossChainDAppEco(appID, chainID string, participantIDs []string, contractData []byte) *CrossChainDAppEco {
	return &CrossChainDAppEco{
		AppID:          appID,
		ChainID:        chainID,
		ParticipantIDs: participantIDs,
		ContractData:   contractData,
		Timestamp:      time.Now(),
		Status:         DAppActive,
	}
}

// UpdateContractData updates the contract data in the decentralized application ecosystem
func (dapp *CrossChainDAppEco) UpdateContractData(newContractData []byte) error {
	dapp.lock.Lock()
	defer dapp.lock.Unlock()

	if dapp.Status != DAppActive {
		return errors.New("cannot update contract data in an inactive or closed ecosystem")
	}

	dapp.ContractData = newContractData
	dapp.Timestamp = time.Now()
	return nil
}

// CloseDAppEco closes the decentralized application ecosystem
func (dapp *CrossChainDAppEco) CloseDAppEco() error {
	dapp.lock.Lock()
	defer dapp.lock.Unlock()

	if dapp.Status != DAppActive {
		return errors.New("ecosystem is not active")
	}

	dapp.Status = DAppClosed
	dapp.Timestamp = time.Now()
	return nil
}

// EncryptDAppEco encrypts the decentralized application ecosystem details
func (dapp *CrossChainDAppEco) EncryptDAppEco(key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s|%s|%s|%s|%s",
		dapp.AppID, dapp.ChainID, dapp.ContractData, dapp.Status, dapp.ParticipantIDs)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDAppEco decrypts the decentralized application ecosystem details
func (dapp *CrossChainDAppEco) DecryptDAppEco(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	parts := utils.Split(string(data), '|')
	if len(parts) != 5 {
		return errors.New("invalid encrypted data format")
	}

	dapp.AppID = parts[0]
	dapp.ChainID = parts[1]
	dapp.ContractData = parts[2]
	dapp.Status = parts[3]
	dapp.ParticipantIDs = utils.Split(parts[4], ',')
	return nil
}

// GetDAppEcoDetails returns the details of the decentralized application ecosystem
func (dapp *CrossChainDAppEco) GetDAppEcoDetails() (string, string, string, string, string) {
	dapp.lock.RLock()
	defer dapp.lock.RUnlock()
	return dapp.AppID, dapp.ChainID, string(dapp.ContractData), dapp.Status, dapp.ParticipantIDs
}

// ValidateDAppEco validates the decentralized application ecosystem details
func (dapp *CrossChainDAppEco) ValidateDAppEco() error {
	dapp.lock.RLock()
	defer dapp.lock.RUnlock()

	if dapp.AppID == "" || dapp.ChainID == "" {
		return errors.New("application and chain IDs cannot be empty")
	}

	if len(dapp.ContractData) == 0 {
		return errors.New("contract data cannot be empty")
	}

	if len(dapp.ParticipantIDs) == 0 {
		return errors.New("participant IDs cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the decentralized application ecosystem
func (dapp *CrossChainDAppEco) UpdateTimestamp() {
	dapp.lock.Lock()
	defer dapp.lock.Unlock()
	dapp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the decentralized application ecosystem
func (dapp *CrossChainDAppEco) GetTimestamp() time.Time {
	dapp.lock.RLock()
	defer dapp.lock.RUnlock()
	return dapp.Timestamp
}
