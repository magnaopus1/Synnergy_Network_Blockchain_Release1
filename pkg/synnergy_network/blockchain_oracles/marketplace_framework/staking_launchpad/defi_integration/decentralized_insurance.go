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

// Policy represents an insurance policy in the decentralized insurance system
type Policy struct {
	ID            string    `json:"id"`
	Holder        string    `json:"holder"`
	Amount        float64   `json:"amount"`
	Premium       float64   `json:"premium"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Claimed       bool      `json:"claimed"`
	ClaimAmount   float64   `json:"claim_amount"`
	CreationTime  time.Time `json:"creation_time"`
	LastUpdated   time.Time `json:"last_updated"`
}

// Claim represents an insurance claim in the decentralized insurance system
type Claim struct {
	ID         string    `json:"id"`
	PolicyID   string    `json:"policy_id"`
	Amount     float64   `json:"amount"`
	Status     string    `json:"status"`
	CreateTime time.Time `json:"create_time"`
	UpdateTime time.Time `json:"update_time"`
}

// DecentralizedInsuranceManager manages insurance policies and claims
type DecentralizedInsuranceManager struct {
	Policies map[string]*Policy
	Claims   map[string]*Claim
	Lock     sync.Mutex
}

// NewDecentralizedInsuranceManager creates a new DecentralizedInsuranceManager instance
func NewDecentralizedInsuranceManager() *DecentralizedInsuranceManager {
	return &DecentralizedInsuranceManager{
		Policies: make(map[string]*Policy),
		Claims:   make(map[string]*Claim),
	}
}

// AddPolicy adds a new insurance policy
func (manager *DecentralizedInsuranceManager) AddPolicy(holder string, amount, premium float64, startTime, endTime time.Time) (*Policy, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(holder + startTime.String() + endTime.String())
	if err != nil {
		return nil, err
	}

	policy := &Policy{
		ID:           id,
		Holder:       holder,
		Amount:       amount,
		Premium:      premium,
		StartTime:    startTime,
		EndTime:      endTime,
		Claimed:      false,
		ClaimAmount:  0,
		CreationTime: time.Now(),
		LastUpdated:  time.Now(),
	}

	manager.Policies[id] = policy
	return policy, nil
}

// GetPolicy retrieves an insurance policy by ID
func (manager *DecentralizedInsuranceManager) GetPolicy(id string) (*Policy, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	policy, exists := manager.Policies[id]
	if !exists {
		return nil, errors.New("policy not found")
	}
	return policy, nil
}

// UpdatePolicy updates an existing insurance policy
func (manager *DecentralizedInsuranceManager) UpdatePolicy(id, holder string, amount, premium float64, startTime, endTime time.Time) (*Policy, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	policy, exists := manager.Policies[id]
	if !exists {
		return nil, errors.New("policy not found")
	}

	policy.Holder = holder
	policy.Amount = amount
	policy.Premium = premium
	policy.StartTime = startTime
	policy.EndTime = endTime
	policy.LastUpdated = time.Now()

	return policy, nil
}

// DeletePolicy deletes an insurance policy by ID
func (manager *DecentralizedInsuranceManager) DeletePolicy(id string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	_, exists := manager.Policies[id]
	if !exists {
		return errors.New("policy not found")
	}

	delete(manager.Policies, id)
	return nil
}

// ListPolicies lists all insurance policies
func (manager *DecentralizedInsuranceManager) ListPolicies() []*Policy {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	policies := make([]*Policy, 0, len(manager.Policies))
	for _, policy := range manager.Policies {
		policies = append(policies, policy)
	}
	return policies
}

// AddClaim adds a new insurance claim
func (manager *DecentralizedInsuranceManager) AddClaim(policyID string, amount float64) (*Claim, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(policyID + time.Now().String())
	if err != nil {
		return nil, err
	}

	claim := &Claim{
		ID:         id,
		PolicyID:   policyID,
		Amount:     amount,
		Status:     "Pending",
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
	}

	manager.Claims[id] = claim
	return claim, nil
}

// GetClaim retrieves an insurance claim by ID
func (manager *DecentralizedInsuranceManager) GetClaim(id string) (*Claim, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	claim, exists := manager.Claims[id]
	if !exists {
		return nil, errors.New("claim not found")
	}
	return claim, nil
}

// UpdateClaim updates an existing insurance claim
func (manager *DecentralizedInsuranceManager) UpdateClaim(id, status string) (*Claim, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	claim, exists := manager.Claims[id]
	if !exists {
		return nil, errors.New("claim not found")
	}

	claim.Status = status
	claim.UpdateTime = time.Now()

	return claim, nil
}

// DeleteClaim deletes an insurance claim by ID
func (manager *DecentralizedInsuranceManager) DeleteClaim(id string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	_, exists := manager.Claims[id]
	if !exists {
		return errors.New("claim not found")
	}

	delete(manager.Claims, id)
	return nil
}

// ListClaims lists all insurance claims
func (manager *DecentralizedInsuranceManager) ListClaims() []*Claim {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	claims := make([]*Claim, 0, len(manager.Claims))
	for _, claim := range manager.Claims {
		claims = append(claims, claim)
	}
	return claims
}

// generateUniqueID generates a unique ID using scrypt for the decentralized insurance entities
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

// APIHandler handles HTTP requests for managing decentralized insurance
type APIHandler struct {
	manager *DecentralizedInsuranceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *DecentralizedInsuranceManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddPolicyHandler handles adding a new insurance policy
func (handler *APIHandler) AddPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var policy Policy
	err := json.NewDecoder(r.Body).Decode(&policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newPolicy, err := handler.manager.AddPolicy(policy.Holder, policy.Amount, policy.Premium, policy.StartTime, policy.EndTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newPolicy)
}

// GetPolicyHandler handles retrieving an insurance policy
func (handler *APIHandler) GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	policy, err := handler.manager.GetPolicy(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// UpdatePolicyHandler handles updating an existing insurance policy
func (handler *APIHandler) UpdatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var policy Policy
	err := json.NewDecoder(r.Body).Decode(&policy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updatedPolicy, err := handler.manager.UpdatePolicy(id, policy.Holder, policy.Amount, policy.Premium, policy.StartTime, policy.EndTime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedPolicy)
}

// DeletePolicyHandler handles deleting an insurance policy
func (handler *APIHandler) DeletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := handler.manager.DeletePolicy(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListPoliciesHandler handles listing all insurance policies
func (handler *APIHandler) ListPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies := handler.manager.ListPolicies()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// AddClaimHandler handles adding a new insurance claim
func (handler *APIHandler) AddClaimHandler(w http.ResponseWriter, r *http.Request) {
	var claim Claim
	err := json.NewDecoder(r.Body).Decode(&claim)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newClaim, err := handler.manager.AddClaim(claim.PolicyID, claim.Amount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newClaim)
}

// GetClaimHandler handles retrieving an insurance claim
func (handler *APIHandler) GetClaimHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	claim, err := handler.manager.GetClaim(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claim)
}

// UpdateClaimHandler handles updating an existing insurance claim
func (handler *APIHandler) UpdateClaimHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var claim Claim
	err := json.NewDecoder(r.Body).Decode(&claim)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updatedClaim, err := handler.manager.UpdateClaim(id, claim.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedClaim)
}

// DeleteClaimHandler handles deleting an insurance claim
func (handler *APIHandler) DeleteClaimHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := handler.manager.DeleteClaim(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListClaimsHandler handles listing all insurance claims
func (handler *APIHandler) ListClaimsHandler(w http.ResponseWriter, r *http.Request) {
	claims := handler.manager.ListClaims()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func main() {
	manager := NewDecentralizedInsuranceManager()
	apiHandler := NewAPIHandler(manager)

	router := mux.NewRouter()
	router.HandleFunc("/policies", apiHandler.AddPolicyHandler).Methods("POST")
	router.HandleFunc("/policies", apiHandler.ListPoliciesHandler).Methods("GET")
	router.HandleFunc("/policies/{id}", apiHandler.GetPolicyHandler).Methods("GET")
	router.HandleFunc("/policies/{id}", apiHandler.UpdatePolicyHandler).Methods("PUT")
	router.HandleFunc("/policies/{id}", apiHandler.DeletePolicyHandler).Methods("DELETE")

	router.HandleFunc("/claims", apiHandler.AddClaimHandler).Methods("POST")
	router.HandleFunc("/claims", apiHandler.ListClaimsHandler).Methods("GET")
	router.HandleFunc("/claims/{id}", apiHandler.GetClaimHandler).Methods("GET")
	router.HandleFunc("/claims/{id}", apiHandler.UpdateClaimHandler).Methods("PUT")
	router.HandleFunc("/claims/{id}", apiHandler.DeleteClaimHandler).Methods("DELETE")

	http.ListenAndServe(":8080", router)
}
