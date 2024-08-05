package collaboration_and_communication

import (
	"errors"
	"log"
	"sync"
	"time"
)

// User represents a user in the collaboration system
type User struct {
	ID       string
	Username string
	Email    string
}

// Message represents a message in the collaboration system
type Message struct {
	ID        string
	Sender    User
	Content   string
	Timestamp time.Time
}

// Channel represents a communication channel
type Channel struct {
	ID       string
	Name     string
	Messages []Message
	Users    []User
}

// CollaborationTools provides tools for team collaboration
type CollaborationTools struct {
	channels map[string]Channel
	mu       sync.Mutex
}

// NewCollaborationTools initializes a new instance of CollaborationTools
func NewCollaborationTools() *CollaborationTools {
	return &CollaborationTools{
		channels: make(map[string]Channel),
	}
}

// CreateChannel creates a new communication channel
func (ct *CollaborationTools) CreateChannel(name string, users []User) (string, error) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	id := generateID(name)
	if _, exists := ct.channels[id]; exists {
		return "", errors.New("channel with this ID already exists")
	}

	channel := Channel{
		ID:    id,
		Name:  name,
		Users: users,
	}
	ct.channels[id] = channel
	log.Printf("Channel created: %s", name)
	return id, nil
}

// SendMessage sends a message in a channel
func (ct *CollaborationTools) SendMessage(channelID, userID, content string) (string, error) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	channel, exists := ct.channels[channelID]
	if !exists {
		return "", errors.New("channel not found")
	}

	user, err := ct.getUser(channelID, userID)
	if err != nil {
		return "", err
	}

	messageID := generateID(content)
	message := Message{
		ID:        messageID,
		Sender:    user,
		Content:   content,
		Timestamp: time.Now(),
	}
	channel.Messages = append(channel.Messages, message)
	ct.channels[channelID] = channel
	log.Printf("Message sent in channel %s by user %s", channelID, userID)
	return messageID, nil
}

// AddUser adds a user to a communication channel
func (ct *CollaborationTools) AddUser(channelID string, user User) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	channel, exists := ct.channels[channelID]
	if !exists {
		return errors.New("channel not found")
	}

	for _, u := range channel.Users {
		if u.ID == user.ID {
			return errors.New("user already in channel")
		}
	}

	channel.Users = append(channel.Users, user)
	ct.channels[channelID] = channel
	log.Printf("User %s added to channel %s", user.Username, channelID)
	return nil
}

// RemoveUser removes a user from a communication channel
func (ct *CollaborationTools) RemoveUser(channelID, userID string) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	channel, exists := ct.channels[channelID]
	if !exists {
		return errors.New("channel not found")
	}

	for i, u := range channel.Users {
		if u.ID == userID {
			channel.Users = append(channel.Users[:i], channel.Users[i+1:]...)
			ct.channels[channelID] = channel
			log.Printf("User %s removed from channel %s", userID, channelID)
			return nil
		}
	}
	return errors.New("user not found in channel")
}

// GetMessages retrieves messages from a communication channel
func (ct *CollaborationTools) GetMessages(channelID string) ([]Message, error) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	channel, exists := ct.channels[channelID]
	if !exists {
		return nil, errors.New("channel not found")
	}

	return channel.Messages, nil
}

// getUser retrieves a user from a channel by their ID
func (ct *CollaborationTools) getUser(channelID, userID string) (User, error) {
	channel, exists := ct.channels[channelID]
	if !exists {
		return User{}, errors.New("channel not found")
	}

	for _, user := range channel.Users {
		if user.ID == userID {
			return user, nil
		}
	}
	return User{}, errors.New("user not found in channel")
}

// generateID generates a unique ID based on the input string
func generateID(input string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(input+time.Now().String())))
}
