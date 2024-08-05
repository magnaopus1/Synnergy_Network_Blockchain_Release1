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

// GovernanceToken represents a token used for governance
type GovernanceToken struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Amount    float64   `json:"amount"`
	CreatedAt time.Time `json:"created_at"`
}

// TokenRequest represents a request for minting governance tokens
type TokenRequest struct {
	Owner  string  `json:"owner"`
	Amount float64 `json:"amount"`
}

// GovernanceTokenManager manages governance tokens
type GovernanceTokenManager struct {
	Tokens map[string]*GovernanceToken
	Lock   sync.Mutex
}

// NewGovernanceTokenManager creates a new GovernanceTokenManager instance
func NewGovernanceTokenManager() *GovernanceTokenManager {
	return &GovernanceTokenManager{
		Tokens: make(map[string]*GovernanceToken),
	}
}

// MintToken mints new governance tokens
func (manager *GovernanceTokenManager) MintToken(request TokenRequest) (*GovernanceToken, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Owner + time.Now().String())
	if err != nil {
		return nil, err
	}

	token := &GovernanceToken{
		ID:        id,
		Owner:     request.Owner,
		Amount:    request.Amount,
		CreatedAt: time.Now(),
	}

	manager.Tokens[id] = token
	return token, nil
}

// GetToken retrieves a governance token by ID
func (manager *GovernanceTokenManager) GetToken(id string) (*GovernanceToken, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	token, exists := manager.Tokens[id]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

// ListTokens lists all governance tokens
func (manager *GovernanceTokenManager) ListTokens() []*GovernanceToken {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	tokens := make([]*GovernanceToken, 0, len(manager.Tokens))
	for _, token := range manager.Tokens {
		tokens = append(tokens, token)
	}
	return tokens
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

// APIHandler handles HTTP requests for governance tokens
type APIHandler struct {
	manager *GovernanceTokenManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *GovernanceTokenManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// MintTokenHandler handles minting governance tokens
func (handler *APIHandler) MintTokenHandler(w http.ResponseWriter, r *http.Request) {
	var request TokenRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newToken, err := handler.manager.MintToken(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newToken)
}

// GetTokenHandler handles retrieving a governance token
func (handler *APIHandler) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	token, err := handler.manager.GetToken(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

// ListTokensHandler handles listing all governance tokens
func (handler *APIHandler) ListTokensHandler(w http.ResponseWriter, r *http.Request) {
	tokens := handler.manager.ListTokens()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/token", handler.MintTokenHandler).Methods("POST")
	r.HandleFunc("/token/{id}", handler.GetTokenHandler).Methods("GET")
	r.HandleFunc("/tokens", handler.ListTokensHandler).Methods("GET")
	return r
}

// main initializes and starts the server
func main() {
	manager := NewGovernanceTokenManager()
	handler := NewAPIHandler(manager)
	router := SetupRouter(handler)

	http.ListenAndServe(":8080", router)
}
