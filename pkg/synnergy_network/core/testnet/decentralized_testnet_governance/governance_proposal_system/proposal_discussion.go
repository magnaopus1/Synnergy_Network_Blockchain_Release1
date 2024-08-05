package governance_proposal_system

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// User represents a user involved in proposal discussions.
type User struct {
	ID       string
	Name     string
	Email    string
	IsAdmin  bool
	JoinDate time.Time
}

// Comment represents a comment made on a proposal.
type Comment struct {
	ID        string
	UserID    string
	Content   string
	Timestamp time.Time
}

// Proposal represents a governance proposal.
type Proposal struct {
	ID          string
	Title       string
	Description string
	AuthorID    string
	Status      string
	Comments    []*Comment
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ProposalDiscussion represents the discussion system for governance proposals.
type ProposalDiscussion struct {
	Proposals map[string]*Proposal
	Users     map[string]*User
	mu        sync.Mutex
}

// NewProposalDiscussion creates a new instance of ProposalDiscussion.
func NewProposalDiscussion() *ProposalDiscussion {
	return &ProposalDiscussion{
		Proposals: make(map[string]*Proposal),
		Users:     make(map[string]*User),
	}
}

// AddUser adds a new user to the proposal discussion system.
func (pd *ProposalDiscussion) AddUser(user *User) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if _, exists := pd.Users[user.ID]; exists {
		return errors.New("user already exists")
	}

	pd.Users[user.ID] = user
	return nil
}

// CreateProposal creates a new proposal.
func (pd *ProposalDiscussion) CreateProposal(title, description, authorID string) (*Proposal, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if _, exists := pd.Users[authorID]; !exists {
		return nil, errors.New("author does not exist")
	}

	proposal := &Proposal{
		ID:          generateID(),
		Title:       title,
		Description: description,
		AuthorID:    authorID,
		Status:      "Pending",
		Comments:    []*Comment{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	pd.Proposals[proposal.ID] = proposal
	return proposal, nil
}

// AddComment adds a comment to a proposal.
func (pd *ProposalDiscussion) AddComment(proposalID, userID, content string) (*Comment, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	proposal, exists := pd.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}

	if _, exists := pd.Users[userID]; !exists {
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
func (pd *ProposalDiscussion) ListProposals() []*Proposal {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	proposals := []*Proposal{}
	for _, proposal := range pd.Proposals {
		proposals = append(proposals, proposal)
	}
	return proposals
}

// GetProposal retrieves a proposal by its ID.
func (pd *ProposalDiscussion) GetProposal(proposalID string) (*Proposal, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	proposal, exists := pd.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}
	return proposal, nil
}

// ListComments lists all comments on a proposal.
func (pd *ProposalDiscussion) ListComments(proposalID string) ([]*Comment, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	proposal, exists := pd.Proposals[proposalID]
	if !exists {
		return nil, errors.New("proposal does not exist")
	}
	return proposal.Comments, nil
}

// ArchiveProposal archives a proposal, changing its status.
func (pd *ProposalDiscussion) ArchiveProposal(proposalID string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	proposal, exists := pd.Proposals[proposalID]
	if !exists {
		return errors.New("proposal does not exist")
	}

	proposal.Status = "Archived"
	proposal.UpdatedAt = time.Now()
	return nil
}

// SearchProposals allows searching for proposals by title or description.
func (pd *ProposalDiscussion) SearchProposals(query string) []*Proposal {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	var results []*Proposal
	for _, proposal := range pd.Proposals {
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
func encryptData(data string, passphrase string) (string, error) {
	// Implement encryption logic using AES with a suitable key derived from the passphrase
	// Consider using Argon2 for key derivation
	return "", nil
}

func decryptData(encryptedData string, passphrase string) (string, error) {
	// Implement decryption logic using AES with a suitable key derived from the passphrase
	// Consider using Argon2 for key derivation
	return "", nil
}

// Improved real-world feature: Vote on comments and proposals
type Vote struct {
	UserID      string
	ProposalID  string
	CommentID   string
	VoteType    string // "upvote" or "downvote"
	Timestamp   time.Time
}

// VotingSystem handles voting on proposals and comments.
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
		UserID:     userID,
		ProposalID: proposalID,
		VoteType:   voteType,
		Timestamp:  time.Now(),
	}
	vs.Votes[generateID()] = vote
	return vote, nil
}

// VoteOnComment allows users to vote on a comment.
func (vs *VotingSystem) VoteOnComment(userID, commentID, voteType string) (*Vote, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	vote := &Vote{
		UserID:    userID,
		CommentID: commentID,
		VoteType:  voteType,
		Timestamp: time.Now(),
	}
	vs.Votes[generateID()] = vote
	return vote, nil
}

// ListVotes lists all votes on proposals and comments.
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
