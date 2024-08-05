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

// LiquidityPool represents a liquidity pool
type LiquidityPool struct {
	PoolID          string
	ParticipantIDs  []string
	LiquidityAmount map[string]int64
	Timestamp       time.Time
	Status          string
	lock            sync.RWMutex
}

const (
	PoolActive   = "ACTIVE"
	PoolInactive = "INACTIVE"
	PoolClosed   = "CLOSED"
)

// NewLiquidityPool initializes a new LiquidityPool instance
func NewLiquidityPool(poolID string, participantIDs []string, initialLiquidity map[string]int64) *LiquidityPool {
	return &LiquidityPool{
		PoolID:          poolID,
		ParticipantIDs:  participantIDs,
		LiquidityAmount: initialLiquidity,
		Timestamp:       time.Now(),
		Status:          PoolActive,
	}
}

// AddLiquidity adds liquidity to the pool
func (lp *LiquidityPool) AddLiquidity(participantID string, amount int64) error {
	lp.lock.Lock()
	defer lp.lock.Unlock()

	if lp.Status != PoolActive {
		return errors.New("cannot add liquidity to an inactive or closed pool")
	}

	lp.LiquidityAmount[participantID] += amount
	lp.Timestamp = time.Now()
	return nil
}

// RemoveLiquidity removes liquidity from the pool
func (lp *LiquidityPool) RemoveLiquidity(participantID string, amount int64) error {
	lp.lock.Lock()
	defer lp.lock.Unlock()

	if lp.Status != PoolActive {
		return errors.New("cannot remove liquidity from an inactive or closed pool")
	}

	if lp.LiquidityAmount[participantID] < amount {
		return errors.New("insufficient liquidity")
	}

	lp.LiquidityAmount[participantID] -= amount
	lp.Timestamp = time.Now()
	return nil
}

// ClosePool closes the liquidity pool
func (lp *LiquidityPool) ClosePool() error {
	lp.lock.Lock()
	defer lp.lock.Unlock()

	if lp.Status != PoolActive {
		return errors.New("pool is not active")
	}

	lp.Status = PoolClosed
	lp.Timestamp = time.Now()
	return nil
}

// EncryptPool encrypts the liquidity pool details
func (lp *LiquidityPool) EncryptPool(key []byte) (string, error) {
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
		lp.PoolID, lp.ParticipantIDs, lp.LiquidityAmount, lp.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPool decrypts the liquidity pool details
func (lp *LiquidityPool) DecryptPool(encryptedData string, key []byte) error {
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

	lp.PoolID = parts[0]
	lp.ParticipantIDs = utils.Split(parts[1], ',')
	lp.LiquidityAmount = utils.ParseLiquidity(parts[2])
	lp.Status = parts[3]
	return nil
}

// GetPoolDetails returns the details of the liquidity pool
func (lp *LiquidityPool) GetPoolDetails() (string, []string, map[string]int64, string) {
	lp.lock.RLock()
	defer lp.lock.RUnlock()
	return lp.PoolID, lp.ParticipantIDs, lp.LiquidityAmount, lp.Status
}

// ValidatePool validates the liquidity pool details
func (lp *LiquidityPool) ValidatePool() error {
	lp.lock.RLock()
	defer lp.lock.RUnlock()

	if lp.PoolID == "" {
		return errors.New("pool ID cannot be empty")
	}

	if len(lp.ParticipantIDs) == 0 {
		return errors.New("participant IDs cannot be empty")
	}

	if len(lp.LiquidityAmount) == 0 {
		return errors.New("liquidity amount cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the liquidity pool
func (lp *LiquidityPool) UpdateTimestamp() {
	lp.lock.Lock()
	defer lp.lock.Unlock()
	lp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the liquidity pool
func (lp *LiquidityPool) GetTimestamp() time.Time {
	lp.lock.RLock()
	defer lp.lock.RUnlock()
	return lp.Timestamp
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

func (lp *LiquidityPool) String() string {
	return fmt.Sprintf("PoolID: %s, Status: %s, Timestamp: %s", lp.PoolID, lp.Status, lp.Timestamp)
}
