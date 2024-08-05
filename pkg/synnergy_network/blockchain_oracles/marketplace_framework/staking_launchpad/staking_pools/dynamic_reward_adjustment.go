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

// Stake represents a single stake made by a user.
type Stake struct {
    UserID     string    `json:"user_id"`
    Amount     *big.Int  `json:"amount"`
    StakedAt   time.Time `json:"staked_at"`
    RewardRate float64   `json:"reward_rate"`
}

// RewardAdjustmentRequest represents a request for adjusting rewards dynamically.
type RewardAdjustmentRequest struct {
    UserID string  `json:"user_id"`
    Amount *big.Int `json:"amount"`
}

// StakingPool represents a pool of stakes with dynamic reward adjustments.
type StakingPool struct {
    Stakes map[string]*Stake
    Lock   sync.Mutex
}

// NewStakingPool creates a new instance of StakingPool.
func NewStakingPool() *StakingPool {
    return &StakingPool{
        Stakes: make(map[string]*Stake),
    }
}

// AddStake adds a new stake to the pool.
func (pool *StakingPool) AddStake(request RewardAdjustmentRequest, rewardRate float64) (*Stake, error) {
    pool.Lock.Lock()
    defer pool.Lock.Unlock()

    if _, exists := pool.Stakes[request.UserID]; exists {
        return nil, errors.New("stake already exists for user")
    }

    id, err := generateUniqueID(request.UserID + time.Now().String())
    if err != nil {
        return nil, err
    }

    stake := &Stake{
        UserID:     id,
        Amount:     request.Amount,
        StakedAt:   time.Now(),
        RewardRate: rewardRate,
    }

    pool.Stakes[id] = stake
    return stake, nil
}

// AdjustRewards dynamically adjusts rewards for all stakes in the pool.
func (pool *StakingPool) AdjustRewards() {
    pool.Lock.Lock()
    defer pool.Lock.Unlock()

    for _, stake := range pool.Stakes {
        reward := calculateReward(stake.Amount, stake.RewardRate)
        stake.Amount.Add(stake.Amount, reward)
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

// APIHandler handles HTTP requests for staking pools.
type APIHandler struct {
    pool *StakingPool
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(pool *StakingPool) *APIHandler {
    return &APIHandler{pool: pool}
}

// AddStakeHandler handles adding new stakes.
func (handler *APIHandler) AddStakeHandler(w http.ResponseWriter, r *http.Request) {
    var request RewardAdjustmentRequest
    err := json.NewDecoder(r.Body).Decode(&request)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    rewardRate := 0.05 // Example reward rate
    newStake, err := handler.pool.AddStake(request, rewardRate)
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

// main initializes and starts the server.
func main() {
    pool := NewStakingPool()
    handler := NewAPIHandler(pool)
    router := SetupRouter(handler)

    fmt.Println("Server started at :8080")
    http.ListenAndServe(":8080", router)
}
