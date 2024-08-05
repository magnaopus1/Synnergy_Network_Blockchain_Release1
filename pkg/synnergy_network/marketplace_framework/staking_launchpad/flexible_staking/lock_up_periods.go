package flexible_staking

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/scrypt"
)

// StakingStatus represents the status of a staking pool
type StakingStatus string

const (
	// Active status for pools that are currently active
	Active StakingStatus = "Active"
	// Inactive status for pools that are inactive
	Inactive StakingStatus = "Inactive"
	// Completed status for pools that have completed their duration
	Completed StakingStatus = "Completed"
)

// StakingPool represents a staking pool in the decentralized staking and lock-up system
type StakingPool struct {
	ID               string        `json:"id"`
	Staker           string        `json:"staker"`
	StakedAmount     float64       `json:"staked_amount"`
	RewardRate       float64       `json:"reward_rate"`
	LockUpPeriod     time.Duration `json:"lock_up_period"`
	Compounding      bool          `json:"compounding"`
	Duration         time.Duration `json:"duration"`
	Status           StakingStatus `json:"status"`
	StartTime        time.Time     `json:"start_time"`
	EndTime          time.Time     `json:"end_time"`
	AccumulatedRewards float64     `json:"accumulated_rewards"`
	LastUpdated      time.Time     `json:"last_updated"`
}

// StakingRequest represents a staking request
type StakingRequest struct {
	Staker       string        `json:"staker"`
	StakedAmount float64       `json:"staked_amount"`
	RewardRate   float64       `json:"reward_rate"`
	LockUpPeriod time.Duration `json:"lock_up_period"`
	Compounding  bool          `json:"compounding"`
	Duration     time.Duration `json:"duration"`
}

// StakingManager manages staking pools and staking requests
type StakingManager struct {
	Pools map[string]*StakingPool
	Lock  sync.Mutex
}

// NewStakingManager creates a new StakingManager instance
func NewStakingManager() *StakingManager {
	return &StakingManager{
		Pools: make(map[string]*StakingPool),
	}
}

// RequestStaking requests a new staking pool
func (manager *StakingManager) RequestStaking(request StakingRequest) (*StakingPool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Staker + time.Now().String())
	if err != nil {
		return nil, err
	}

	pool := &StakingPool{
		ID:               id,
		Staker:           request.Staker,
		StakedAmount:     request.StakedAmount,
		RewardRate:       request.RewardRate,
		LockUpPeriod:     request.LockUpPeriod,
		Compounding:      request.Compounding,
		Duration:         request.Duration,
		Status:           Active,
		StartTime:        time.Now(),
		EndTime:          time.Now().Add(request.Duration),
		AccumulatedRewards: 0,
		LastUpdated:      time.Now(),
	}

	manager.Pools[id] = pool
	return pool, nil
}

// UpdateStaking updates the rewards for a staking pool
func (manager *StakingManager) UpdateStaking(id string) (*StakingPool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return nil, errors.New("pool not found")
	}

	if pool.Status != Active {
		return nil, errors.New("pool is not active")
	}

	elapsedTime := time.Since(pool.LastUpdated).Seconds()
	rewards := elapsedTime * pool.StakedAmount * (pool.RewardRate / 100)
	if pool.Compounding {
		rewards += pool.AccumulatedRewards * (pool.RewardRate / 100)
	}
	pool.AccumulatedRewards += rewards
	pool.LastUpdated = time.Now()

	if time.Now().After(pool.EndTime) {
		pool.Status = Completed
	}

	return pool, nil
}

// GetStakingPool retrieves a staking pool by ID
func (manager *StakingManager) GetStakingPool(id string) (*StakingPool, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return nil, errors.New("pool not found")
	}
	return pool, nil
}

// ListStakingPools lists all staking pools
func (manager *StakingManager) ListStakingPools() []*StakingPool {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pools := make([]*StakingPool, 0, len(manager.Pools))
	for _, pool := range manager.Pools {
		pools = append(pools, pool)
	}
	return pools
}

// WithdrawStakedAmount allows the staker to withdraw their staked amount after the lock-up period has ended
func (manager *StakingManager) WithdrawStakedAmount(id string) (float64, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	pool, exists := manager.Pools[id]
	if !exists {
		return 0, errors.New("pool not found")
	}

	if time.Now().Before(pool.EndTime) {
		return 0, errors.New("lock-up period has not ended")
	}

	withdrawableAmount := pool.StakedAmount + pool.AccumulatedRewards
	delete(manager.Pools, id)

	return withdrawableAmount, nil
}

// generateUniqueID generates a unique ID using scrypt for the decentralized staking entities
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

// generateSalt generates a salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// APIHandler handles HTTP requests for managing decentralized staking and lock-up periods
type APIHandler struct {
	manager *StakingManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *StakingManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// RequestStakingHandler handles staking requests
func (handler *APIHandler) RequestStakingHandler(w http.ResponseWriter, r *http.Request) {
	var request StakingRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newPool, err := handler.manager.RequestStaking(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newPool)
}

// UpdateStakingHandler handles staking updates
func (handler *APIHandler) UpdateStakingHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	updatedPool, err := handler.manager.UpdateStaking(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedPool)
}

// GetStakingPoolHandler handles retrieving a staking pool
func (handler *APIHandler) GetStakingPoolHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	pool, err := handler.manager.GetStakingPool(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pool)
}

// ListStakingPoolsHandler handles listing all staking pools
func (handler *APIHandler) ListStakingPoolsHandler(w http.ResponseWriter, r *http.Request) {
	pools := handler.manager.ListStakingPools()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pools)
}

// WithdrawStakedAmountHandler handles withdrawing the staked amount after the lock-up period
func (handler *APIHandler) WithdrawStakedAmountHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	withdrawableAmount, err := handler.manager.WithdrawStakedAmount(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]float64{"withdrawable_amount": withdrawableAmount})
}

func main() {
	manager := NewStakingManager()
	apiHandler := NewAPIHandler(manager)

	router := mux.NewRouter()
	router.HandleFunc("/pools", apiHandler.RequestStakingHandler).Methods("POST")
	router.HandleFunc("/pools", apiHandler.ListStakingPoolsHandler).Methods("GET")
	router.HandleFunc("/pools/{id}", apiHandler.GetStakingPoolHandler).Methods("GET")
	router.HandleFunc("/pools/{id}/update", apiHandler.UpdateStakingHandler).Methods("POST")
	router.HandleFunc("/pools/{id}/withdraw", apiHandler.WithdrawStakedAmountHandler).Methods("POST")

	http.ListenAndServe(":8080", router)
}
