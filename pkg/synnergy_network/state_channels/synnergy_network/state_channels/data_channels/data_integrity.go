package data_channels

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/utils"
)

// DataIntegrity represents the integrity verification mechanism for data channels
type DataIntegrity struct {
	ChannelID  string
	DataHash   []byte
	Timestamp  time.Time
	Verified   bool
	lock       sync.RWMutex
}

// NewDataIntegrity initializes a new DataIntegrity instance
func NewDataIntegrity(channelID string, data []byte) *DataIntegrity {
	return &DataIntegrity{
		ChannelID: channelID,
		DataHash:  hashData(data),
		Timestamp: time.Now(),
		Verified:  false,
	}
}

// hashData computes the SHA-256 hash of the data
func hashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// VerifyDataIntegrity verifies the integrity of the data
func (di *DataIntegrity) VerifyDataIntegrity(data []byte) error {
	di.lock.Lock()
	defer di.lock.Unlock()

	newDataHash := hashData(data)
	if !utils.Equal(di.DataHash, newDataHash) {
		return errors.New("data integrity verification failed")
	}

	di.Verified = true
	return nil
}

// IsVerified returns the verification status of the data
func (di *DataIntegrity) IsVerified() bool {
	di.lock.RLock()
	defer di.lock.RUnlock()

	return di.Verified
}

func (di *DataIntegrity) String() string {
	return fmt.Sprintf("ChannelID: %s, Verified: %t, Timestamp: %s", di.ChannelID, di.Verified, di.Timestamp)
}

// GetDataHash returns the hash of the data
func (di *DataIntegrity) GetDataHash() []byte {
	di.lock.RLock()
	defer di.lock.RUnlock()
	return di.DataHash
}

// UpdateDataHash updates the hash of the data
func (di *DataIntegrity) UpdateDataHash(data []byte) {
	di.lock.Lock()
	defer di.lock.Unlock()
	di.DataHash = hashData(data)
	di.Timestamp = time.Now()
	di.Verified = false
}

// CompareDataHash compares the given data with the stored hash
func (di *DataIntegrity) CompareDataHash(data []byte) bool {
	di.lock.RLock()
	defer di.lock.RUnlock()
	newDataHash := hashData(data)
	return utils.Equal(di.DataHash, newDataHash)
}

// ValidateDataHash performs validation on the data hash
func (di *DataIntegrity) ValidateDataHash(data []byte) error {
	if len(data) == 0 {
		return errors.New("data cannot be empty")
	}

	if !di.CompareDataHash(data) {
		return errors.New("data does not match the stored hash")
	}

	return nil
}

// ResetVerification resets the verification status
func (di *DataIntegrity) ResetVerification() {
	di.lock.Lock()
	defer di.lock.Unlock()
	di.Verified = false
}

// UpdateTimestamp updates the timestamp of the data integrity
func (di *DataIntegrity) UpdateTimestamp() {
	di.lock.Lock()
	defer di.lock.Unlock()
	di.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the data integrity
func (di *DataIntegrity) GetTimestamp() time.Time {
	di.lock.RLock()
	defer di.lock.RUnlock()
	return di.Timestamp
}

// SetVerified sets the verified status of the data integrity
func (di *DataIntegrity) SetVerified(verified bool) {
	di.lock.Lock()
	defer di.lock.Unlock()
	di.Verified = verified
}
