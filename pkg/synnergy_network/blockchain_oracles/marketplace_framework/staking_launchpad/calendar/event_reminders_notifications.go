package calendar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Constants for encryption
const (
	ScryptN = 32768
	ScryptR = 8
	ScryptP = 1
	KeyLen  = 32
)

// Event represents a calendar event with a reminder
type Event struct {
	ID          string
	Title       string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	Reminder    time.Time
	Notified    bool
}

// EventManager manages events and their reminders
type EventManager struct {
	Events map[string]*Event
	Lock   sync.Mutex
}

// NewEventManager creates a new EventManager instance
func NewEventManager() *EventManager {
	return &EventManager{
		Events: make(map[string]*Event),
	}
}

// AddEvent adds a new event to the manager
func (manager *EventManager) AddEvent(title, description string, startTime, endTime, reminder time.Time) (*Event, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(fmt.Sprintf("%s-%s", title, description))
	if err != nil {
		return nil, err
	}

	event := &Event{
		ID:          id,
		Title:       title,
		Description: description,
		StartTime:   startTime,
		EndTime:     endTime,
		Reminder:    reminder,
		Notified:    false,
	}

	manager.Events[id] = event
	return event, nil
}

// GetEvent retrieves an event by ID
func (manager *EventManager) GetEvent(id string) (*Event, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	event, exists := manager.Events[id]
	if !exists {
		return nil, errors.New("event not found")
	}
	return event, nil
}

// UpdateEvent updates an existing event
func (manager *EventManager) UpdateEvent(id, title, description string, startTime, endTime, reminder time.Time) (*Event, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	event, exists := manager.Events[id]
	if !exists {
		return nil, errors.New("event not found")
	}

	event.Title = title
	event.Description = description
	event.StartTime = startTime
	event.EndTime = endTime
	event.Reminder = reminder

	return event, nil
}

// DeleteEvent deletes an event by ID
func (manager *EventManager) DeleteEvent(id string) error {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	_, exists := manager.Events[id]
	if !exists {
		return errors.New("event not found")
	}

	delete(manager.Events, id)
	return nil
}

// CheckReminders checks for events that need reminders sent
func (manager *EventManager) CheckReminders() {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	now := time.Now()
	for _, event := range manager.Events {
		if !event.Notified && event.Reminder.Before(now) {
			// Send notification (implementation depends on the notification system used)
			// Example: sendNotification(event)
			event.Notified = true
		}
	}
}

// Encryption and decryption functions
func encrypt(data, passphrase string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

func decrypt(encrypted, passphrase string) (string, error) {
	parts := split(encrypted, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted data format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, KeyLen)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func generateUniqueID(input string) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s", input, hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func split(s, sep string) []string {
	var parts []string
	for len(s) > 0 {
		pos := len(s)
		if i := len(s) - len(sep); i >= 0 {
			if s[i:] == sep {
				pos = i
			}
		}
		parts = append(parts, s[:pos])
		s = s[pos+len(sep):]
	}
	return parts
}

// sendNotification simulates sending a notification for an event
// Replace this with the actual implementation for sending notifications
func sendNotification(event *Event) {
	fmt.Printf("Reminder: Event '%s' is starting soon!\n", event.Title)
}
