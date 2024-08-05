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

// Proposal represents a governance proposal
type Proposal struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Creator      string    `json:"creator"`
	CreatedAt    time.Time `json:"created_at"`
	VotesFor     int       `json:"votes_for"`
	VotesAgainst int       `json:"votes_against"`
}

// ProposalRequest represents a request for creating a proposal
type ProposalRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Creator     string `json:"creator"`
}

// VoteRequest represents a request for voting on a proposal
type VoteRequest struct {
	ProposalID string `json:"proposal_id"`
	Voter      string `json:"voter"`
	Vote       bool   `json:"vote"` // true for 'for', false for 'against'
}

// ProposalManager manages governance proposals
type ProposalManager struct {
	Proposals map[string]*Proposal
	Lock      sync.Mutex
}

// NewProposalManager creates a new ProposalManager instance
func NewProposalManager() *ProposalManager {
	return &ProposalManager{
		Proposals: make(map[string]*Proposal),
	}
}

// CreateProposal creates a new proposal
func (manager *ProposalManager) CreateProposal(request ProposalRequest) (*Proposal, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(request.Creator + time.Now().String())
	if err != nil {
		return nil, err
	}

	proposal := &Proposal{
		ID:          id,
		Title:       request.Title,
		Description: request.Description,
		Creator:     request.Creator,
		CreatedAt:   time.Now(),
	}

	manager.Proposals[id] = proposal
	return proposal, nil
}

// GetProposal retrieves a proposal by ID
func (manager *ProposalManager) GetProposal(id string) (*Proposal, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	proposal, exists := manager.Proposals[id]
	if !exists {
		return nil, errors.New("proposal not found")
	}
	return proposal, nil
}

// ListProposals lists all proposals
func (manager *ProposalManager) ListProposals() []*Proposal {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	proposals := make([]*Proposal, 0, len(manager.Proposals))
	for _, proposal := range manager.Proposals {
		proposals = append(proposals, proposal)
	}
	return proposals
}

// VoteOnProposal allows voting on a proposal
func (manager *ProposalManager) VoteOnProposal(request VoteRequest) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	proposal, exists := manager.Proposals[request.ProposalID]
	if !exists {
		return errors.New("proposal not found")
	}

	if request.Vote {
		proposal.VotesFor++
	} else {
		proposal.VotesAgainst++
	}

	return nil
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

// APIHandler handles HTTP requests for governance proposals
type APIHandler struct {
	manager *ProposalManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(manager *ProposalManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// CreateProposalHandler handles creating governance proposals
func (handler *APIHandler) CreateProposalHandler(w http.ResponseWriter, r *http.Request) {
	var request ProposalRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newProposal, err := handler.manager.CreateProposal(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newProposal)
}

// GetProposalHandler handles retrieving a governance proposal
func (handler *APIHandler) GetProposalHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	proposal, err := handler.manager.GetProposal(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proposal)
}

// ListProposalsHandler handles listing all governance proposals
func (handler *APIHandler) ListProposalsHandler(w http.ResponseWriter, r *http.Request) {
	proposals := handler.manager.ListProposals()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proposals)
}

// VoteOnProposalHandler handles voting on governance proposals
func (handler *APIHandler) VoteOnProposalHandler(w http.ResponseWriter, r *http.Request) {
	var request VoteRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = handler.manager.VoteOnProposal(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// SetupRouter sets up the HTTP router
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/proposal", handler.CreateProposalHandler).Methods("POST")
	r.HandleFunc("/proposal/{id}", handler.GetProposalHandler).Methods("GET")
	r.HandleFunc("/proposals", handler.ListProposalsHandler).Methods("GET")
	r.HandleFunc("/proposal/vote", handler.VoteOnProposalHandler).Methods("POST")
	return r
}

// main initializes and starts the server
func main() {
	manager := NewProposalManager()
	handler := NewAPIHandler(manager)
	router := SetupRouter(handler)

	http.ListenAndServe(":8080", router)
}
