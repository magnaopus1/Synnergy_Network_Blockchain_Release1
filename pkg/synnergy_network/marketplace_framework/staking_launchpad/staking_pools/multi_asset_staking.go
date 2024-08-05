package staking_pools

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "math/big"
    "sync"
    "time"

    "github.com/gorilla/mux"
    "golang.org/x/crypto/scrypt"
    "net/http"
)

// Stake represents a single stake made by a user in a specific asset.
type Stake struct {
    UserID     string    `json:"user_id"`
    Asset      string    `json:"asset"`
    Amount     *big.Int  `json:"amount"`
    StakedAt   time.Time `json:"staked_at"`
    RewardRate float64   `json:"reward_rate"`
}

// MultiAssetStakingPool represents a pool of stakes for multiple assets.
type MultiAssetStakingPool struct {
    Stakes map[string]map[string]*Stake // Map of userID to map of asset to Stake
    Lock   sync.Mutex
}

// NewMultiAssetStakingPool creates a new instance of MultiAssetStakingPool.
func NewMultiAssetStakingPool() *MultiAssetStakingPool {
    return &MultiAssetStakingPool{
        Stakes: make(map[string]map[string]*Stake),
    }
}

// AddStake adds a new stake to the pool.
func (pool *MultiAssetStakingPool) AddStake(request StakeRequest) (*Stake, error) {
    pool.Lock.Lock()
    defer pool.Lock.Unlock()

    if _, exists := pool.Stakes[request.UserID]; !exists {
        pool.Stakes[request.UserID] = make(map[string]*Stake)
    }

    if _, exists := pool.Stakes[request.UserID][request.Asset]; exists {
        return nil, errors.New("stake already exists for user and asset")
    }

    id, err := generateUniqueID(request.UserID + request.Asset + time.Now().String())
    if err != nil {
        return nil, err
    }

    stake := &Stake{
        UserID:     id,
        Asset:      request.Asset,
        Amount:     request.Amount,
        StakedAt:   time.Now(),
        RewardRate: request.RewardRate,
    }

    pool.Stakes[request.UserID][request.Asset] = stake
    return stake, nil
}

// AdjustRewards dynamically adjusts rewards for all stakes in the pool.
func (pool *MultiAssetStakingPool) AdjustRewards() {
    pool.Lock.Lock()
    defer pool.Lock.Unlock()

    for _, userStakes := range pool.Stakes {
        for _, stake := range userStakes {
            reward := calculateReward(stake.Amount, stake.RewardRate)
            stake.Amount.Add(stake.Amount, reward)
        }
    }
}

// calculateReward calculates the reward based on the amount and reward rate.
func calculateReward(amount *big.Int, rewardRate float64) *big.Int {
    reward := new(big.Float).Mul(new(big.Float).SetInt(amount), big.NewFloat(rewardRate))
    rewardInt, _ := reward.Int(nil)
    return rewardInt
}

// generateUniqueID generates a unique ID using scrypt.
func generateUniqueID(input string) (string, error) {
    salt, err := generateSalt()
    if err != nil {
        return "", err
    }
    dk, err := scrypt.Key([]byte(input), salt, 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    hash := sha256.Sum256(dk)
    return hex.EncodeToString(hash[:]), nil
}

// generateSalt generates a salt for hashing.
func generateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    return salt, err
}

// StakeRequest represents a request for staking.
type StakeRequest struct {
    UserID     string  `json:"user_id"`
    Asset      string  `json:"asset"`
    Amount     *big.Int `json:"amount"`
    RewardRate float64 `json:"reward_rate"`
}

// APIHandler handles HTTP requests for the multi-asset staking pool.
type APIHandler struct {
    pool *MultiAssetStakingPool
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(pool *MultiAssetStakingPool) *APIHandler {
    return &APIHandler{pool: pool}
}

// AddStakeHandler handles adding new stakes.
func (handler *APIHandler) AddStakeHandler(w http.ResponseWriter, r *http.Request) {
    var request StakeRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newStake, err := handler.pool.AddStake(request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newStake)
}

// AdjustRewardsHandler handles adjusting rewards dynamically.
func (handler *APIHandler) AdjustRewardsHandler(w http.ResponseWriter, r *http.Request) {
    handler.pool.AdjustRewards()

    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"rewards adjusted successfully"}`))
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/stake", handler.AddStakeHandler).Methods("POST")
    r.HandleFunc("/adjust_rewards", handler.AdjustRewardsHandler).Methods("POST")
    return r
}

// Encryption and decryption utilities for additional security
func encrypt(data []byte, passphrase string) ([]byte, error) {
    block, _ := aes.NewCipher([]byte(createHash(passphrase)))
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
    key := []byte(createHash(passphrase))
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
    return plaintext, nil
}

func createHash(key string) string {
    hash := sha256.New()
    hash.Write([]byte(key))
    return hex.EncodeToString(hash.Sum(nil))
}
