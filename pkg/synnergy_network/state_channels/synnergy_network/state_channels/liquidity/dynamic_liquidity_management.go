package liquidity

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

// DynamicLiquidityManagement represents the dynamic liquidity management mechanism
type DynamicLiquidityManagement struct {
	PoolID          string
	ParticipantIDs  []string
	LiquidityAmount map[string]int64
	Timestamp       time.Time
	Status          string
	lock            sync.RWMutex
}

const (
	LiquidityActive   = "ACTIVE"
	LiquidityInactive = "INACTIVE"
	LiquidityClosed   = "CLOSED"
)

// NewDynamicLiquidityManagement initializes a new DynamicLiquidityManagement instance
func NewDynamicLiquidityManagement(poolID string, participantIDs []string, initialLiquidity map[string]int64) *DynamicLiquidityManagement {
	return &DynamicLiquidityManagement{
		PoolID:          poolID,
		ParticipantIDs:  participantIDs,
		LiquidityAmount: initialLiquidity,
		Timestamp:       time.Now(),
		Status:          LiquidityActive,
	}
}

// AddLiquidity adds liquidity to the pool
func (dlm *DynamicLiquidityManagement) AddLiquidity(participantID string, amount int64) error {
	dlm.lock.Lock()
	defer dlm.lock.Unlock()

	if dlm.Status != LiquidityActive {
		return errors.New("cannot add liquidity to an inactive or closed pool")
	}

	dlm.LiquidityAmount[participantID] += amount
	dlm.Timestamp = time.Now()
	return nil
}

// RemoveLiquidity removes liquidity from the pool
func (dlm *DynamicLiquidityManagement) RemoveLiquidity(participantID string, amount int64) error {
	dlm.lock.Lock()
	defer dlm.lock.Unlock()

	if dlm.Status != LiquidityActive {
		return errors.New("cannot remove liquidity from an inactive or closed pool")
	}

	if dlm.LiquidityAmount[participantID] < amount {
		return errors.New("insufficient liquidity")
	}

	dlm.LiquidityAmount[participantID] -= amount
	dlm.Timestamp = time.Now()
	return nil
}

// ClosePool closes the liquidity pool
func (dlm *DynamicLiquidityManagement) ClosePool() error {
	dlm.lock.Lock()
	defer dlm.lock.Unlock()

	if dlm.Status != LiquidityActive {
		return errors.New("pool is not active")
	}

	dlm.Status = LiquidityClosed
	dlm.Timestamp = time.Now()
	return nil
}

// EncryptLiquidity encrypts the liquidity pool details
func (dlm *DynamicLiquidityManagement) EncryptLiquidity(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s",
		dlm.PoolID, dlm.ParticipantIDs, dlm.LiquidityAmount, dlm.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptLiquidity decrypts the liquidity pool details
func (dlm *DynamicLiquidityManagement) DecryptLiquidity(encryptedData string, key []byte) error {
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
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	dlm.PoolID = parts[0]
	dlm.ParticipantIDs = utils.Split(parts[1], ',')
	dlm.LiquidityAmount = utils.ParseLiquidity(parts[2])
	dlm.Status = parts[3]
	return nil
}

// GetLiquidityDetails returns the details of the liquidity pool
func (dlm *DynamicLiquidityManagement) GetLiquidityDetails() (string, []string, map[string]int64, string) {
	dlm.lock.RLock()
	defer dlm.lock.RUnlock()
	return dlm.PoolID, dlm.ParticipantIDs, dlm.LiquidityAmount, dlm.Status
}

// ValidateLiquidity validates the liquidity pool details
func (dlm *DynamicLiquidityManagement) ValidateLiquidity() error {
	dlm.lock.RLock()
	defer dlm.lock.RUnlock()

	if dlm.PoolID == "" {
		return errors.New("pool ID cannot be empty")
	}

	if len(dlm.ParticipantIDs) == 0 {
		return errors.New("participant IDs cannot be empty")
	}

	if len(dlm.LiquidityAmount) == 0 {
		return errors.New("liquidity amount cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the liquidity pool
func (dlm *DynamicLiquidityManagement) UpdateTimestamp() {
	dlm.lock.Lock()
	defer dlm.lock.Unlock()
	dlm.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the liquidity pool
func (dlm *DynamicLiquidityManagement) GetTimestamp() time.Time {
	dlm.lock.RLock()
	defer dlm.lock.RUnlock()
	return dlm.Timestamp
}

// GenerateKey generates a cryptographic key using Argon2
func GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (dlm *DynamicLiquidityManagement) String() string {
	return fmt.Sprintf("PoolID: %s, Status: %s, Timestamp: %s", dlm.PoolID, dlm.Status, dlm.Timestamp)
}
