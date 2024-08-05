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

// CrossChainStateChannel represents a state channel for cross-chain interoperability
type CrossChainStateChannel struct {
	ChannelID      string
	ChainAID       string
	ChainBID       string
	ParticipantIDs []string
	StateData      []byte
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	StateChannelActive   = "ACTIVE"
	StateChannelInactive = "INACTIVE"
	StateChannelClosed   = "CLOSED"
)

// NewCrossChainStateChannel initializes a new CrossChainStateChannel instance
func NewCrossChainStateChannel(channelID, chainAID, chainBID string, participantIDs []string, stateData []byte) *CrossChainStateChannel {
	return &CrossChainStateChannel{
			ChannelID:      channelID,
			ChainAID:       chainAID,
			ChainBID:       chainBID,
			ParticipantIDs: participantIDs,
			StateData:      stateData,
			Timestamp:      time.Now(),
			Status:         StateChannelActive,
		}
	}

// UpdateStateData updates the state data in the cross-chain state channel
func (ccsc *CrossChainStateChannel) UpdateStateData(newStateData []byte) error {
	ccsc.lock.Lock()
	defer ccsc.lock.Unlock()

	if ccsc.Status != StateChannelActive {
		return errors.New("cannot update state data in an inactive or closed state channel")
	}

	ccsc.StateData = newStateData
	ccsc.Timestamp = time.Now()
	return nil
}

// CloseStateChannel closes the cross-chain state channel
func (ccsc *CrossChainStateChannel) CloseStateChannel() error {
	ccsc.lock.Lock()
	defer ccsc.lock.Unlock()

	if ccsc.Status != StateChannelActive {
		return errors.New("state channel is not active")
	}

	ccsc.Status = StateChannelClosed
	ccsc.Timestamp = time.Now()
	return nil
}

// EncryptStateChannel encrypts the cross-chain state channel details
func (ccsc *CrossChainStateChannel) EncryptStateChannel(key []byte) (string, error) {
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
		ccsc.ChannelID, ccsc.ChainAID, ccsc.ChainBID, ccsc.StateData, ccsc.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptStateChannel decrypts the cross-chain state channel details
func (ccsc *CrossChainStateChannel) DecryptStateChannel(encryptedData string, key []byte) error {
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

	ccsc.ChannelID = parts[0]
	ccsc.ChainAID = parts[1]
	ccsc.ChainBID = parts[2]
	ccsc.StateData = parts[3]
	ccsc.Status = parts[4]
	return nil
}

// GetStateChannelDetails returns the details of the cross-chain state channel
func (ccsc *CrossChainStateChannel) GetStateChannelDetails() (string, string, string, string, string) {
	ccsc.lock.RLock()
	defer ccsc.lock.RUnlock()
	return ccsc.ChannelID, ccsc.ChainAID, ccsc.ChainBID, string(ccsc.StateData), ccsc.Status
}

// ValidateStateChannel validates the cross-chain state channel details
func (ccsc *CrossChainStateChannel) ValidateStateChannel() error {
	ccsc.lock.RLock()
	defer ccsc.lock.RUnlock()

	if ccsc.ChannelID == "" || ccsc.ChainAID == "" || ccsc.ChainBID == "" {
		return errors.New("channel and chain IDs cannot be empty")
	}

	if len(ccsc.StateData) == 0 {
		return errors.New("state data cannot be empty")
	}

	if len(ccsc.ParticipantIDs) == 0 {
		return errors.New("participant IDs cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the cross-chain state channel
func (ccsc *CrossChainStateChannel) UpdateTimestamp() {
	ccsc.lock.Lock()
	defer ccsc.lock.Unlock()
	ccsc.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the cross-chain state channel
func (ccsc *CrossChainStateChannel) GetTimestamp() time.Time {
	ccsc.lock.RLock()
	defer ccsc.lock.RUnlock()
	return ccsc.Timestamp
}
