package voting_mechanism

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Vote represents a single vote in a governance proposal.
type Vote struct {
	UserID    string
	VoteType  string // "yes" or "no"
	Timestamp time.Time
}

// Proposal represents a governance proposal.
type Proposal struct {
	ID          string
	Title       string
	Description string
	AuthorID    string
	Status      string
	Votes       map[string]*Vote
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// User represents a user in the governance system.
type User struct {
	ID         string
	Name       string
	Email      string
	JoinDate   time.Time
	Reputation int
}

// VotingPlatform represents the voting platform for decentralized governance.
type VotingPlatform struct {
	Users     map[string]*User
	Proposals map[string]*Proposal
	mu        sync.Mutex
}

// NewVotingPlatform creates a new instance of VotingPlatform.
func NewVotingPlatform() *VotingPlatform {
	return &VotingPlatform{
		Users:     make(map[string]*User),
		Proposals: make(map[string]*Proposal),
	}
}

// AddUser adds a new user to the platform.
func (vp *VotingPlatform) AddUser(name, email string) (*User, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	id := generateID()
	user := &User{
		ID:         id,
		Name:       name,
		Email:      email,
		JoinDate:   time.Now(),
		Reputation: 0,
	}

	vp.Users[id] = user
	return user, nil
}

// CreateProposal creates a new governance proposal.
func (vp *VotingPlatform) CreateProposal(title, description, authorID string) (*Proposal, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if _, exists := vp.Users[authorID]; !exists {
		return nil, errors.New("author does not exist")
	}

	id := generateID()
	proposal := &Proposal{
		ID:          id,
		Title:       title,
		Description: description,
		AuthorID:    authorID,
		Status:      "Pending",
		Votes:       make(map[string]*Vote),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	vp.Proposals[id] = proposal
	return proposal, nil
}

// VoteOnProposal allows a user to vote on a proposal.
func (vp *VotingPlatform) VoteOnProposal(userID, proposalID, voteType string) (*Vote, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if _, exists := vp.Users[userID]; !exists {
		return nil, errors.New("user does not exist")
	}

	proposal, exists := vp.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}

	vote := &Vote{
		UserID:    userID,
		VoteType:  voteType,
		Timestamp: time.Now(),
	}

	proposal.Votes[generateID()] = vote
	proposal.UpdatedAt = time.Now()
	return vote, nil
}

// CloseProposal closes a proposal and sets its status to "Closed".
func (vp *VotingPlatform) CloseProposal(proposalID string) error {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	proposal, exists := vp.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	proposal.Status = "Closed"
	proposal.UpdatedAt = time.Now()
	return nil
}

// GetProposalResult calculates and returns the result of a proposal.
func (vp *VotingPlatform) GetProposalResult(proposalID string) (string, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	proposal, exists := vp.Proposals[proposalID]
	if !exists {
		return "", errors.New("proposal does not exist")
	}

	var yesVotes, noVotes int
	for _, vote := range proposal.Votes {
		if vote.VoteType == "yes" {
			yesVotes++
		} else if vote.VoteType == "no" {
			noVotes++
		}
	}

	result := fmt.Sprintf("Yes: %d, No: %d", yesVotes, noVotes)
	return result, nil
}

// ExportProposals exports all proposals to a JSON string.
func (vp *VotingPlatform) ExportProposals() (string, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	data, err := json.Marshal(vp.Proposals)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ImportProposals imports proposals from a JSON string.
func (vp *VotingPlatform) ImportProposals(data string) error {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	var proposals map[string]*Proposal
	if err := json.Unmarshal([]byte(data), &proposals); err != nil {
		return err
	}

	for id, proposal := range proposals {
		vp.Proposals[id] = proposal
	}

	return nil
}

// generateID generates a unique ID for users, proposals, and votes.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// contains checks if a string contains a substring.
func contains(source, substr string) bool {
	return strings.Contains(strings.ToLower(source), strings.ToLower(substr))
}

// Comprehensive feature: Notifications for users
type Notification struct {
	ID        string
	UserID    string
	Message   string
	Timestamp time.Time
}

// NotificationSystem handles sending notifications to users.
type NotificationSystem struct {
	Notifications map[string]*Notification
	mu            sync.Mutex
}

// NewNotificationSystem creates a new instance of NotificationSystem.
func NewNotificationSystem() *NotificationSystem {
	return &NotificationSystem{
		Notifications: make(map[string]*Notification),
	}
}

// SendNotification sends a notification to a user.
func (ns *NotificationSystem) SendNotification(userID, message string) (*Notification, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	notification := &Notification{
		ID:        generateID(),
		UserID:    userID,
		Message:   message,
		Timestamp: time.Now(),
	}
	ns.Notifications[notification.ID] = notification
	return notification, nil
}

// ListNotifications lists all notifications for a user.
func (ns *NotificationSystem) ListNotifications(userID string) []*Notification {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	var notifications []*Notification
	for _, notification := range ns.Notifications {
		if notification.UserID == userID {
			notifications = append(notifications, notification)
		}
	}
	return notifications
}

// Encryption and Decryption using Argon2 and AES
func generateKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
}

// encryptAES encrypts data using AES.
func encryptAES(data, passphrase string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := generateKey(passphrase, salt)
	// Implement AES encryption logic using key
	return "", nil
}

// decryptAES decrypts data using AES.
func decryptAES(encryptedData, passphrase string) (string, error) {
	// Implement AES decryption logic
	return "", nil
}

// Feature: Exporting and Importing Users
func (vp *VotingPlatform) ExportUsers() (string, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	data, err := json.Marshal(vp.Users)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (vp *VotingPlatform) ImportUsers(data string) error {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	var users map[string]*User
	if err := json.Unmarshal([]byte(data), &users); err != nil {
		return err
	}

	for id, user := range users {
		vp.Users[id] = user
	}

	return nil
}
