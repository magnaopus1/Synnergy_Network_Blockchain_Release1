package governance

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

// IncentiveType represents the type of incentive for governance participation
type IncentiveType string

const (
	// TokenReward represents a reward in tokens
	TokenReward IncentiveType = "TokenReward"
	// ReputationPoints represents a reward in reputation points
	ReputationPoints IncentiveType = "ReputationPoints"
)

// GovernanceIncentive represents an incentive for governance participation
type GovernanceIncentive struct {
	ID           string        `json:"id"`
	Participant  string        `json:"participant"`
	Type         IncentiveType `json:"type"`
	Amount       float64       `json:"amount"`
	GrantedAt    time.Time     `json:"granted_at"`
	Description  string        `json:"description"`
}

// IncentiveRequest represents a request for granting an incentive
type IncentiveRequest struct {
	Participant string        `json:"participant"`
	Type        IncentiveType `json:"type"`
	Amount      float64       `json:"amount"`
	Description string        `json:"description"`
}

// GovernanceManager manages governance incentives
type GovernanceManager struct {
	Incentives map[string]*GovernanceIncentive
	Lock       sync.Mutex
}

// NewGovernanceManager creates a new GovernanceManager instance
func NewGovernanceManager() *GovernanceManager {
	return &GovernanceManager{
		Incentives: make(map[string]*GovernanceIncentive),
	}
}

// GrantIncentive grants a new incentive
func (manager *GovernanceManager) GrantIncentive(request IncentiveRequest) (*GovernanceIncentive, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Participant + time.Now().String())
	if err != nil {
		return nil, err
	}

	incentive := &GovernanceIncentive{
		ID:           id,
		Participant:  request.Participant,
		Type:         request.Type,
		Amount:       request.Amount,
		GrantedAt:    time.Now(),
		Description:  request.Description,
	}

	manager.Incentives[id] = incentive
	return incentive, nil
}

// GetIncentive retrieves an incentive by ID
func (manager *GovernanceManager) GetIncentive(id string) (*GovernanceIncentive, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	incentive, exists := manager.Incentives[id]
	if !exists {
		return nil, errors.New("incentive not found")
	}
	return incentive, nil
}

// ListIncentives lists all incentives
func (manager *GovernanceManager) ListIncentives() []*GovernanceIncentive {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	incentives := make([]*GovernanceIncentive, 0, len(manager.Incentives))
	for _, incentive := range manager.Incentives {
		incentives = append(incentives, incentive)
	}
	return incentives
}

// generateUniqueID generates a unique ID using scrypt
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

// APIHandler handles HTTP requests for governance incentives
type APIHandler struct {
	manager *GovernanceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *GovernanceManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// GrantIncentiveHandler handles granting incentives
func (handler *APIHandler) GrantIncentiveHandler(w http.ResponseWriter, r *http.Request) {
	var request IncentiveRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newIncentive, err := handler.manager.GrantIncentive(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newIncentive)
}

// GetIncentiveHandler handles retrieving an incentive
func (handler *APIHandler) GetIncentiveHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	incentive, err := handler.manager.GetIncentive(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incentive)
}

// ListIncentivesHandler handles listing all incentives
func (handler *APIHandler) ListIncentivesHandler(w http.ResponseWriter, r *http.Request) {
	incentives := handler.manager.ListIncentives()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incentives)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/incentive", handler.GrantIncentiveHandler).Methods("POST")
	r.HandleFunc("/incentive/{id}", handler.GetIncentiveHandler).Methods("GET")
	r.HandleFunc("/incentives", handler.ListIncentivesHandler).Methods("GET")
	return r
}

// main initializes and starts the server
func main() {
	manager := NewGovernanceManager()
	handler := NewAPIHandler(manager)
	router := SetupRouter(handler)

	http.ListenAndServe(":8080", router)
}
