package defi_integration

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

// FarmStatus represents the status of a yield farm
type FarmStatus string

const (
	// Active status for farms that are currently active
	Active FarmStatus = "Active"
	// Inactive status for farms that are inactive
	Inactive FarmStatus = "Inactive"
	// Completed status for farms that have completed their duration
	Completed FarmStatus = "Completed"
)

// YieldFarm represents a yield farm in the decentralized yield farming and liquidity mining system
type YieldFarm struct {
	ID           string     `json:"id"`
	Farmer       string     `json:"farmer"`
	StakedAmount float64    `json:"staked_amount"`
	RewardRate   float64    `json:"reward_rate"`
	Duration     time.Duration `json:"duration"`
	Status       FarmStatus `json:"status"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      time.Time  `json:"end_time"`
	Rewards      float64    `json:"rewards"`
	LastUpdated  time.Time  `json:"last_updated"`
}

// FarmRequest represents a yield farm request
type FarmRequest struct {
	Farmer       string     `json:"farmer"`
	StakedAmount float64    `json:"staked_amount"`
	RewardRate   float64    `json:"reward_rate"`
	Duration     time.Duration `json:"duration"`
}

// FarmManager manages yield farms and farm requests
type FarmManager struct {
	Farms map[string]*YieldFarm
	Lock  sync.Mutex
}

// NewFarmManager creates a new FarmManager instance
func NewFarmManager() *FarmManager {
	return &FarmManager{
		Farms: make(map[string]*YieldFarm),
	}
}

// RequestFarm requests a new yield farm
func (manager *FarmManager) RequestFarm(request FarmRequest) (*YieldFarm, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Farmer + time.Now().String())
	if err != nil {
		return nil, err
	}

	farm := &YieldFarm{
		ID:           id,
		Farmer:       request.Farmer,
		StakedAmount: request.StakedAmount,
		RewardRate:   request.RewardRate,
		Duration:     request.Duration,
		Status:       Active,
		StartTime:    time.Now(),
		EndTime:      time.Now().Add(request.Duration),
		Rewards:      0,
		LastUpdated:  time.Now(),
	}

	manager.Farms[id] = farm
	return farm, nil
}

// UpdateFarm updates the rewards for a yield farm
func (manager *FarmManager) UpdateFarm(id string) (*YieldFarm, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	farm, exists := manager.Farms[id]
	if !exists {
		return nil, errors.New("farm not found")
	}

	if farm.Status != Active {
		return nil, errors.New("farm is not active")
	}

	elapsedTime := time.Since(farm.LastUpdated).Seconds()
	rewards := elapsedTime * farm.StakedAmount * (farm.RewardRate / 100)
	farm.Rewards += rewards
	farm.LastUpdated = time.Now()

	if time.Now().After(farm.EndTime) {
		farm.Status = Completed
	}

	return farm, nil
}

// GetFarm retrieves a yield farm by ID
func (manager *FarmManager) GetFarm(id string) (*YieldFarm, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	farm, exists := manager.Farms[id]
	if !exists {
		return nil, errors.New("farm not found")
	}
	return farm, nil
}

// ListFarms lists all yield farms
func (manager *FarmManager) ListFarms() []*YieldFarm {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	farms := make([]*YieldFarm, 0, len(manager.Farms))
	for _, farm := range manager.Farms {
		farms = append(farms, farm)
	}
	return farms
}

// generateUniqueID generates a unique ID using scrypt for the decentralized yield farming entities
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

// APIHandler handles HTTP requests for managing decentralized yield farming and liquidity mining
type APIHandler struct {
	manager *FarmManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *FarmManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// RequestFarmHandler handles farm requests
func (handler *APIHandler) RequestFarmHandler(w http.ResponseWriter, r *http.Request) {
	var request FarmRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newFarm, err := handler.manager.RequestFarm(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newFarm)
}

// UpdateFarmHandler handles farm updates
func (handler *APIHandler) UpdateFarmHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	updatedFarm, err := handler.manager.UpdateFarm(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedFarm)
}

// GetFarmHandler handles retrieving a farm
func (handler *APIHandler) GetFarmHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	farm, err := handler.manager.GetFarm(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(farm)
}

// ListFarmsHandler handles listing all farms
func (handler *APIHandler) ListFarmsHandler(w http.ResponseWriter, r *http.Request) {
	farms := handler.manager.ListFarms()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(farms)
}

func main() {
	manager := NewFarmManager()
	apiHandler := NewAPIHandler(manager)

	router := mux.NewRouter()
	router.HandleFunc("/farms", apiHandler.RequestFarmHandler).Methods("POST")
	router.HandleFunc("/farms", apiHandler.ListFarmsHandler).Methods("GET")
	router.HandleFunc("/farms/{id}", apiHandler.GetFarmHandler).Methods("GET")
	router.HandleFunc("/farms/{id}/update", apiHandler.UpdateFarmHandler).Methods("POST")

	http.ListenAndServe(":8080", router)
}
