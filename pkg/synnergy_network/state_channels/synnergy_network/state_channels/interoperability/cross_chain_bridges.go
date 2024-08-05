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

// CrossChainBridge represents a bridge for cross-chain interoperability
type CrossChainBridge struct {
	BridgeID       string
	ChainAID       string
	ChainBID       string
	ParticipantIDs []string
	AmountA        int64
	AmountB        int64
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	BridgeActive   = "ACTIVE"
	BridgeInactive = "INACTIVE"
	BridgeClosed   = "CLOSED"
)

// NewCrossChainBridge initializes a new CrossChainBridge instance
func NewCrossChainBridge(bridgeID, chainAID, chainBID string, participantIDs []string, amountA, amountB int64) *CrossChainBridge {
	return &CrossChainBridge{
		BridgeID:       bridgeID,
		ChainAID:       chainAID,
		ChainBID:       chainBID,
		ParticipantIDs: participantIDs,
		AmountA:        amountA,
		AmountB:        amountB,
		Timestamp:      time.Now(),
		Status:         BridgeActive,
	}
}

// UpdateAmounts updates the amounts in the cross-chain bridge
func (ccb *CrossChainBridge) UpdateAmounts(newAmountA, newAmountB int64) error {
	ccb.lock.Lock()
	defer ccb.lock.Unlock()

	if ccb.Status != BridgeActive {
		return errors.New("cannot update amounts in an inactive or closed bridge")
	}

	ccb.AmountA = newAmountA
	ccb.AmountB = newAmountB
	ccb.Timestamp = time.Now()
	return nil
}

// CloseBridge closes the cross-chain bridge
func (ccb *CrossChainBridge) CloseBridge() error {
	ccb.lock.Lock()
	defer ccb.lock.Unlock()

	if ccb.Status != BridgeActive {
		return errors.New("bridge is not active")
	}

	ccb.Status = BridgeClosed
	ccb.Timestamp = time.Now()
	return nil
}

// EncryptBridge encrypts the cross-chain bridge details
func (ccb *CrossChainBridge) EncryptBridge(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%d|%d|%s|%s",
		ccb.BridgeID, ccb.ChainAID, ccb.ChainBID, ccb.AmountA, ccb.AmountB, ccb.Status, ccb.ParticipantIDs)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptBridge decrypts the cross-chain bridge details
func (ccb *CrossChainBridge) DecryptBridge(encryptedData string, key []byte) error {
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
	if len(parts) != 7 {
		return errors.New("invalid encrypted data format")
	}

	ccb.BridgeID = parts[0]
	ccb.ChainAID = parts[1]
	ccb.ChainBID = parts[2]
	ccb.AmountA = utils.ParseInt64(parts[3])
	ccb.AmountB = utils.ParseInt64(parts[4])
	ccb.Status = parts[5]
	ccb.ParticipantIDs = utils.Split(parts[6], ',')
	return nil
}

// GetBridgeDetails returns the details of the cross-chain bridge
func (ccb *CrossChainBridge) GetBridgeDetails() (string, string, string, int64, int64, string) {
	ccb.lock.RLock()
	defer ccb.lock.RUnlock()
	return ccb.BridgeID, ccb.ChainAID, ccb.ChainBID, ccb.AmountA, ccb.AmountB, ccb.Status
}

// ValidateBridge validates the cross-chain bridge details
func (ccb *CrossChainBridge) ValidateBridge() error {
	ccb.lock.RLock()
	defer ccb.lock.RUnlock()

	if ccb.BridgeID == "" || ccb.ChainAID == "" || ccb.ChainBID == "" {
		return errors.New("bridge and chain IDs cannot be empty")
	}

	if ccb.AmountA <= 0 || ccb.AmountB <= 0 {
		return errors.New("amounts must be greater than zero")
	}

	if len(ccb.ParticipantIDs) == 0 {
		return errors.New("participant IDs cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the cross-chain bridge
func (ccb *CrossChainBridge) UpdateTimestamp() {
	ccb.lock.Lock()
	defer ccb.lock.Unlock()
	ccb.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the cross-chain bridge
func (ccb *CrossChainBridge) GetTimestamp() time.Time {
	ccb.lock.RLock()
	defer ccb.lock.RUnlock()
	return ccb.Timestamp
}
