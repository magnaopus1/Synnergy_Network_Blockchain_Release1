package vetting

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
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/gorilla/mux"
)

// CommunityVote represents a vote from the community for a project.
type CommunityVote struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"project_id"`
	VoterID    string    `json:"voter_id"`
	VoteValue  int       `json:"vote_value"` // 1 for upvote, -1 for downvote
	Timestamp  time.Time `json:"timestamp"`
}

// CommunityVotingManager manages the community voting process.
type CommunityVotingManager struct {
	votes map[string]*CommunityVote
	lock  sync.Mutex
}

// NewCommunityVotingManager creates a new instance of CommunityVotingManager.
func NewCommunityVotingManager() *CommunityVotingManager {
	return &CommunityVotingManager{
		votes: make(map[string]*CommunityVote),
	}
}

// AddVote adds a new community vote.
func (manager *CommunityVotingManager) AddVote(projectID, voterID string, voteValue int) (*CommunityVote, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	id, err := generateUniqueID(projectID + voterID)
	if err != nil {
		return nil, err
	}

	vote := &CommunityVote{
		ID:         id,
		ProjectID:  projectID,
		VoterID:    voterID,
		VoteValue:  voteValue,
		Timestamp:  time.Now(),
	}

	manager.votes[id] = vote
	return vote, nil
}

// GetVote retrieves a community vote by its ID.
func (manager *CommunityVotingManager) GetVote(id string) (*CommunityVote, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	vote, exists := manager.votes[id]
	if !exists {
		return nil, errors.New("vote not found")
	}
	return vote, nil
}

// ListVotes lists all community votes for a given project.
func (manager *CommunityVotingManager) ListVotes(projectID string) ([]*CommunityVote, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	var votes []*CommunityVote
	for _, vote := range manager.votes {
		if vote.ProjectID == projectID {
			votes = append(votes, vote)
		}
	}
	return votes, nil
}

// TallyVotes tallies the votes for a given project.
func (manager *CommunityVotingManager) TallyVotes(projectID string) (int, error) {
	manager.lock.Lock()
	defer manager.lock.Unlock()

	var tally int
	for _, vote := range manager.votes {
		if vote.ProjectID == projectID {
			tally += vote.VoteValue
		}
	}
	return tally, nil
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

// APIHandler handles HTTP requests for the community voting.
type APIHandler struct {
	manager *CommunityVotingManager
}

// NewAPIHandler creates a new APIHandler.
func NewAPIHandler(manager *CommunityVotingManager) *APIHandler {
	return &APIHandler{manager: manager}
}

// AddVoteHandler handles adding new community votes.
func (handler *APIHandler) AddVoteHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ProjectID string `json:"project_id"`
		VoterID   string `json:"voter_id"`
		VoteValue int    `json:"vote_value"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newVote, err := handler.manager.AddVote(request.ProjectID, request.VoterID, request.VoteValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newVote)
}

// GetVoteHandler handles retrieving a community vote.
func (handler *APIHandler) GetVoteHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	vote, err := handler.manager.GetVote(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vote)
}

// ListVotesHandler handles listing all community votes for a project.
func (handler *APIHandler) ListVotesHandler(w http.ResponseWriter, r *http.Request) {
	projectID := mux.Vars(r)["project_id"]
	votes, err := handler.manager.ListVotes(projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(votes)
}

// TallyVotesHandler handles tallying the votes for a project.
func (handler *APIHandler) TallyVotesHandler(w http.ResponseWriter, r *http.Request) {
	projectID := mux.Vars(r)["project_id"]
	tally, err := handler.manager.TallyVotes(projectID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"tally": tally})
}

// SetupRouter sets up the HTTP router.
func SetupRouter(handler *APIHandler) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/community_votes", handler.AddVoteHandler).Methods("POST")
	r.HandleFunc("/community_votes/{id}", handler.GetVoteHandler).Methods("GET")
	r.HandleFunc("/community_votes/project/{project_id}", handler.ListVotesHandler).Methods("GET")
	r.HandleFunc("/community_votes/tally/{project_id}", handler.TallyVotesHandler).Methods("GET")
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
