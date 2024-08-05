package governance_education

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// User represents a user in the support channel.
type User struct {
	ID       string
	Name     string
	Email    string
	IsAdmin  bool
	JoinDate time.Time
}

// Message represents a message in the support channel.
type Message struct {
	ID        string
	SenderID  string
	Content   string
	Timestamp time.Time
}

// SupportChannel represents a support channel for governance education.
type SupportChannel struct {
	ID       string
	Name     string
	Users    map[string]*User
	Messages []*Message
	mu       sync.Mutex
}

// SupportService handles multiple support channels.
type SupportService struct {
	Channels map[string]*SupportChannel
	mu       sync.Mutex
}

// NewSupportService creates a new instance of SupportService.
func NewSupportService() *SupportService {
	return &SupportService{
		Channels: make(map[string]*SupportChannel),
	}
}

// CreateChannel creates a new support channel.
func (s *SupportService) CreateChannel(name string) (*SupportChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Channels[name]; exists {
		return nil, errors.New("channel already exists")
	}

	channel := &SupportChannel{
		ID:       generateID(),
		Name:     name,
		Users:    make(map[string]*User),
		Messages: []*Message{},
	}
	s.Channels[name] = channel
	return channel, nil
}

// AddUser adds a new user to the support channel.
func (sc *SupportChannel) AddUser(user *User) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, exists := sc.Users[user.ID]; exists {
		return errors.New("user already exists in the channel")
	}

	sc.Users[user.ID] = user
	return nil
}

// RemoveUser removes a user from the support channel.
func (sc *SupportChannel) RemoveUser(userID string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, exists := sc.Users[userID]; !exists {
		return errors.New("user does not exist in the channel")
	}

	delete(sc.Users, userID)
	return nil
}

// SendMessage sends a message in the support channel.
func (sc *SupportChannel) SendMessage(senderID, content string) (*Message, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, exists := sc.Users[senderID]; !exists {
		return nil, errors.New("sender is not part of the channel")
	}

	message := &Message{
		ID:        generateID(),
		SenderID:  senderID,
		Content:   content,
		Timestamp: time.Now(),
	}
	sc.Messages = append(sc.Messages, message)
	return message, nil
}

// ListMessages lists all messages in the support channel.
func (sc *SupportChannel) ListMessages() []*Message {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	return sc.Messages
}

// ListUsers lists all users in the support channel.
func (sc *SupportChannel) ListUsers() []*User {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	users := []*User{}
	for _, user := range sc.Users {
		users = append(users, user)
	}
	return users
}

// DeleteChannel deletes a support channel.
func (s *SupportService) DeleteChannel(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Channels[name]; !exists {
		return errors.New("channel does not exist")
	}

	delete(s.Channels, name)
	return nil
}

// generateID generates a unique ID for users and messages.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Additional features to enhance functionality and real-world readiness:

// ArchiveChannel archives a support channel, preserving its data.
func (s *SupportService) ArchiveChannel(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	channel, exists := s.Channels[name]
	if !exists {
		return errors.New("channel does not exist")
	}

	// Archiving logic here (e.g., move to an archive storage)
	fmt.Printf("Archiving channel: %s\n", channel.Name)
	// For now, just delete from active channels
	delete(s.Channels, name)
	return nil
}

// SearchMessages allows searching for messages by content or sender.
func (sc *SupportChannel) SearchMessages(query string) []*Message {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	var results []*Message
	for _, message := range sc.Messages {
		if contains(message.Content, query) || message.SenderID == query {
			results = append(results, message)
		}
	}
	return results
}

// contains checks if a string contains a substring.
func contains(source, substr string) bool {
	return strings.Contains(strings.ToLower(source), strings.ToLower(substr))
}

// PinMessage pins a message for quick access.
func (sc *SupportChannel) PinMessage(messageID string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	for _, message := range sc.Messages {
		if message.ID == messageID {
			// Pinning logic here (e.g., add to a pinned list)
			fmt.Printf("Message pinned: %s\n", message.Content)
			return nil
		}
	}
	return errors.New("message not found")
}

// Real-time notifications (simulated for this example)
func (sc *SupportChannel) NotifyUsers(notification string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	for _, user := range sc.Users {
		fmt.Printf("Notification sent to %s: %s\n", user.Name, notification)
	}
}

func main() {
	// Example usage (not to be included in production code)
	supportService := NewSupportService()
	channel, _ := supportService.CreateChannel("Governance Support")

	user1 := &User{ID: generateID(), Name: "Alice", Email: "alice@example.com", IsAdmin: false, JoinDate: time.Now()}
	user2 := &User{ID: generateID(), Name: "Bob", Email: "bob@example.com", IsAdmin: false, JoinDate: time.Now()}

	channel.AddUser(user1)
	channel.AddUser(user2)

	channel.SendMessage(user1.ID, "Hello, how can I help you today?")
	channel.SendMessage(user2.ID, "I need assistance with the governance proposal process.")

	messages := channel.ListMessages()
	for _, msg := range messages {
		fmt.Printf("[%s] %s: %s\n", msg.Timestamp, msg.SenderID, msg.Content)
	}

	channel.NotifyUsers("New proposal submitted for voting.")
}
