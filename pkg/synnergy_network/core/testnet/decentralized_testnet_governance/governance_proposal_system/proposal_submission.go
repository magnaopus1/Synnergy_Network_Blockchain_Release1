package governance_proposal_system

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// User represents a user involved in the governance system.
type User struct {
	ID       string
	Name     string
	Email    string
	IsAdmin  bool
	JoinDate time.Time
}

// Proposal represents a governance proposal.
type Proposal struct {
	ID          string
	Title       string
	Description string
	AuthorID    string
	Status      string
	Votes       map[string]Vote
	Comments    []*Comment
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Comment represents a comment on a proposal.
type Comment struct {
	ID        string
	UserID    string
	Content   string
	Timestamp time.Time
}

// Vote represents a vote on a proposal.
type Vote struct {
	UserID    string
	VoteType  string // "upvote" or "downvote"
	Timestamp time.Time
}

// ProposalSubmission represents the system for submitting and managing proposals.
type ProposalSubmission struct {
	Proposals map[string]*Proposal
	Users     map[string]*User
	mu        sync.Mutex
}

// NewProposalSubmission creates a new instance of ProposalSubmission.
func NewProposalSubmission() *ProposalSubmission {
	return &ProposalSubmission{
		Proposals: make(map[string]*Proposal),
		Users:     make(map[string]*User),
	}
}

// AddUser adds a new user to the proposal submission system.
func (ps *ProposalSubmission) AddUser(user *User) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.Users[user.ID]; exists {
		return errors.New("user already exists")
	}

	ps.Users[user.ID] = user
	return nil
}

// CreateProposal creates a new proposal.
func (ps *ProposalSubmission) CreateProposal(title, description, authorID string) (*Proposal, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.Users[authorID]; !exists {
		return nil, errors.New("author does not exist")
	}

	proposal := &Proposal{
		ID:          generateID(),
		Title:       title,
		Description: description,
		AuthorID:    authorID,
		Status:      "Pending",
		Votes:       make(map[string]Vote),
		Comments:    []*Comment{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	ps.Proposals[proposal.ID] = proposal
	return proposal, nil
}

// AddComment adds a comment to a proposal.
func (ps *ProposalSubmission) AddComment(proposalID, userID, content string) (*Comment, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	proposal, exists := ps.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}

	if _, exists := ps.Users[userID]; !exists {
		return nil, errors.New("user does not exist")
	}

	comment := &Comment{
		ID:        generateID(),
		UserID:    userID,
		Content:   content,
		Timestamp: time.Now(),
	}
	proposal.Comments = append(proposal.Comments, comment)
	proposal.UpdatedAt = time.Now()
	return comment, nil
}

// ListProposals lists all proposals.
func (ps *ProposalSubmission) ListProposals() []*Proposal {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	proposals := []*Proposal{}
	for _, proposal := range ps.Proposals {
		proposals = append(proposals, proposal)
	}
	return proposals
}

// GetProposal retrieves a proposal by its ID.
func (ps *ProposalSubmission) GetProposal(proposalID string) (*Proposal, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	proposal, exists := ps.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}
	return proposal, nil
}

// ListComments lists all comments on a proposal.
func (ps *ProposalSubmission) ListComments(proposalID string) ([]*Comment, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	proposal, exists := ps.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}
	return proposal.Comments, nil
}

// ArchiveProposal archives a proposal, changing its status.
func (ps *ProposalSubmission) ArchiveProposal(proposalID string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	proposal, exists := ps.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	proposal.Status = "Archived"
	proposal.UpdatedAt = time.Now()
	return nil
}

// SearchProposals allows searching for proposals by title or description.
func (ps *ProposalSubmission) SearchProposals(query string) []*Proposal {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	var results []*Proposal
	for _, proposal := range ps.Proposals {
		if contains(proposal.Title, query) || contains(proposal.Description, query) {
			results = append(results, proposal)
		}
	}
	return results
}

// contains checks if a string contains a substring.
func contains(source, substr string) bool {
	return strings.Contains(strings.ToLower(source), strings.ToLower(substr))
}

// generateID generates a unique ID for users, comments, and proposals.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Encryption and Decryption for sensitive data (e.g., proposals, comments)
func encryptData(data, passphrase string) (string, error) {
	// Placeholder for AES encryption logic using a key derived from the passphrase
	return "", nil
}

func decryptData(encryptedData, passphrase string) (string, error) {
	// Placeholder for AES decryption logic using a key derived from the passphrase
	return "", nil
}

// Improved real-world feature: Vote on comments and proposals
type VotingSystem struct {
	Votes map[string]*Vote
	mu    sync.Mutex
}

// NewVotingSystem creates a new instance of VotingSystem.
func NewVotingSystem() *VotingSystem {
	return &VotingSystem{
		Votes: make(map[string]*Vote),
	}
}

// VoteOnProposal allows users to vote on a proposal.
func (vs *VotingSystem) VoteOnProposal(userID, proposalID, voteType string) (*Vote, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	vote := &Vote{
		UserID:    userID,
		VoteType:  voteType,
		Timestamp: time.Now(),
	}
	vs.Votes[generateID()] = vote
	return vote, nil
}

// ListVotes lists all votes on proposals.
func (vs *VotingSystem) ListVotes() []*Vote {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	votes := []*Vote{}
	for _, vote := range vs.Votes {
		votes = append(votes, vote)
	}
	return votes
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

// Placeholder functions for encryption and decryption using Argon2 and AES
func generateKey(passphrase string, salt []byte) []byte {
	return argon2.Key([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// Placeholder for AES encryption logic
func encryptAES(data, passphrase string) (string, error) {
	return "", nil
}

// Placeholder for AES decryption logic
func decryptAES(encryptedData, passphrase string) (string, error) {
	return "", nil
}
