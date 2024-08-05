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
    "net/http"
    "sync"
    "time"

    "github.com/gorilla/mux"
    "golang.org/x/crypto/scrypt"
)

// RewardType represents the type of reward in the staking pool.
type RewardType string

const (
    FixedReward    RewardType = "fixed"
    VariableReward RewardType = "variable"
)

// Stake represents a single stake made by a user.
type Stake struct {
    UserID       string      `json:"user_id"`
    Amount       *big.Int    `json:"amount"`
    StakedAt     time.Time   `json:"staked_at"`
    RewardType   RewardType  `json:"reward_type"`
    RewardRate   float64     `json:"reward_rate"`
    LastClaimed  time.Time   `json:"last_claimed"`
    ClaimedReward *big.Int   `json:"claimed_reward"`
}

// RewardStructure defines the structure of the rewards in the staking pool.
type RewardStructure struct {
    PoolID     string             `json:"pool_id"`
    Stakes     map[string]*Stake  `json:"stakes"`
    Lock       sync.Mutex         `json:"-"`
}

// NewRewardStructure creates a new reward structure.
func NewRewardStructure(poolID string) *RewardStructure {
    return &RewardStructure{
        PoolID: poolID,
        Stakes: make(map[string]*Stake),
    }
}

// AddStake adds a new stake to the reward structure.
func (rs *RewardStructure) AddStake(userID string, amount *big.Int, rewardType RewardType, rewardRate float64) (*Stake, error) {
    rs.Lock.Lock()
    defer rs.Lock.Unlock()

    if _, exists := rs.Stakes[userID]; exists {
        return nil, errors.New("stake already exists for user")
    }

    stake := &Stake{
        UserID:       userID,
        Amount:       amount,
        StakedAt:     time.Now(),
        RewardType:   rewardType,
        RewardRate:   rewardRate,
        LastClaimed:  time.Now(),
        ClaimedReward: big.NewInt(0),
    }

    rs.Stakes[userID] = stake
    return stake, nil
}

// ClaimReward allows a user to claim their reward.
func (rs *RewardStructure) ClaimReward(userID string) (*big.Int, error) {
    rs.Lock.Lock()
    defer rs.Lock.Unlock()

    stake, exists := rs.Stakes[userID]
    if !exists {
        return nil, errors.New("stake does not exist for user")
    }

    reward := calculateReward(stake)
    stake.LastClaimed = time.Now()
    stake.ClaimedReward.Add(stake.ClaimedReward, reward)

    return reward, nil
}

// calculateReward calculates the reward based on the stake details.
func calculateReward(stake *Stake) *big.Int {
    duration := time.Since(stake.LastClaimed).Hours() / 24
    reward := new(big.Float).Mul(new(big.Float).SetInt(stake.Amount), big.NewFloat(stake.RewardRate*duration))
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

// APIHandler handles HTTP requests for the staking pool.
type APIHandler struct {
    rewardStructure *RewardStructure
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(rs *RewardStructure) *APIHandler {
    return &APIHandler{rewardStructure: rs}
}

// AddStakeHandler handles adding new stakes.
func (handler *APIHandler) AddStakeHandler(w http.ResponseWriter, r *http.Request) {
    var request struct {
        UserID     string  `json:"user_id"`
        Amount     *big.Int `json:"amount"`
        RewardType RewardType `json:"reward_type"`
        RewardRate float64 `json:"reward_rate"`
    }
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newStake, err := handler.rewardStructure.AddStake(request.UserID, request.Amount, request.RewardType, request.RewardRate)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(newStake)
}

// ClaimRewardHandler handles reward claims.
func (handler *APIHandler) ClaimRewardHandler(w http.ResponseWriter, r *http.Request) {
    var request struct {
        UserID string `json:"user_id"`
    }
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    reward, err := handler.rewardStructure.ClaimReward(request.UserID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "user_id": request.UserID,
        "reward":  reward,
    })
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
    r := mux.NewRouter()
    r.HandleFunc("/stake", handler.AddStakeHandler).Methods("POST")
    r.HandleFunc("/claim_reward", handler.ClaimRewardHandler).Methods("POST")
    return r
}

// Encryption and decryption utilities for additional security.
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
