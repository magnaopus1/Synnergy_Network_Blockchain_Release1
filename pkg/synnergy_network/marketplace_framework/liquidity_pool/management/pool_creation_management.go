package management

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// PoolCreationManagement handles the creation and management of liquidity pools
type PoolCreationManagement struct {
	Pools         map[string]*LiquidityPool
	Lock          sync.Mutex
}

// LiquidityPool represents a liquidity pool with its ID, token balances, and parameters
type LiquidityPool struct {
	ID            common.Hash
	TokenBalances map[string]*big.Float
	Parameters    *PoolParameters
}

// PoolParameters represents the configurable parameters of a liquidity pool
type PoolParameters struct {
	SwapFee       *big.Float
	WithdrawalFee *big.Float
	DepositFee    *big.Float
}

// NewPoolCreationManagement creates a new PoolCreationManagement instance
func NewPoolCreationManagement() *PoolCreationManagement {
	return &PoolCreationManagement{
		Pools: make(map[string]*LiquidityPool),
	}
}

// CreatePool creates a new liquidity pool with the given initial parameters and token balances
func (pcm *PoolCreationManagement) CreatePool(initialBalances map[string]*big.Float, initialParameters *PoolParameters) (common.Hash, error) {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	poolID, err := generatePoolID()
	if err != nil {
		return common.Hash{}, err
	}

	pool := &LiquidityPool{
		ID:            poolID,
		TokenBalances: initialBalances,
		Parameters:    initialParameters,
	}
	pcm.Pools[poolID.Hex()] = pool

	return poolID, nil
}

// generatePoolID generates a unique identifier for a liquidity pool
func generatePoolID() (common.Hash, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(id), nil
}

// GetPool retrieves a liquidity pool by its ID
func (pcm *PoolCreationManagement) GetPool(poolID common.Hash) (*LiquidityPool, error) {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pool, exists := pcm.Pools[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	return pool, nil
}

// UpdatePoolParameters updates the parameters of a specific liquidity pool
func (pcm *PoolCreationManagement) UpdatePoolParameters(poolID common.Hash, newParameters *PoolParameters) error {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pool, exists := pcm.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	pool.Parameters = newParameters
	return nil
}

// ListPools lists all the liquidity pools
func (pcm *PoolCreationManagement) ListPools() []*LiquidityPool {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pools := []*LiquidityPool{}
	for _, pool := range pcm.Pools {
		pools = append(pools, pool)
	}

	return pools
}

// AddLiquidity adds liquidity to a specific pool
func (pcm *PoolCreationManagement) AddLiquidity(poolID common.Hash, token string, amount *big.Float) error {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pool, exists := pcm.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	balance, exists := pool.TokenBalances[token]
	if !exists {
		pool.TokenBalances[token] = big.NewFloat(0)
		balance = pool.TokenBalances[token]
	}

	balance.Add(balance, amount)
	return nil
}

// RemoveLiquidity removes liquidity from a specific pool
func (pcm *PoolCreationManagement) RemoveLiquidity(poolID common.Hash, token string, amount *big.Float) error {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pool, exists := pcm.Pools[poolID.Hex()]
	if !exists {
		return errors.New("pool not found")
	}

	balance, exists := pool.TokenBalances[token]
	if !exists {
		return errors.New("token not found in pool")
	}

	if balance.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}

	balance.Sub(balance, amount)
	return nil
}

// GetPoolBalances retrieves the token balances of a specific pool
func (pcm *PoolCreationManagement) GetPoolBalances(poolID common.Hash) (map[string]*big.Float, error) {
	pcm.Lock.Lock()
	defer pcm.Lock.Unlock()

	pool, exists := pcm.Pools[poolID.Hex()]
	if !exists {
		return nil, errors.New("pool not found")
	}

	return pool.TokenBalances, nil
}

// EncryptData encrypts data using AES encryption
func EncryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts AES encrypted data
func DecryptData(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// HashPassword hashes a password using Argon2
func HashPassword(password string, salt []byte) (string, error) {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// VerifyPassword verifies a hashed password using Argon2
func VerifyPassword(password string, salt []byte, hashedPassword string) (bool, error) {
	hash, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false, err
	}
	computedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// GenerateSalt generates a random salt for password hashing
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
