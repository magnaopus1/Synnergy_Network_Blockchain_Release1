package events

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// Event represents a blockchain event.
type Event struct {
	ID        string
	Type      string
	Timestamp int64
	Data      map[string]interface{}
}

// EventListener defines the interface for an event listener.
type EventListener interface {
	HandleEvent(event Event) error
}

// EventDispatcher is responsible for managing and dispatching events.
type EventDispatcher struct {
	listeners map[string][]EventListener
}

// NewEventDispatcher creates a new EventDispatcher instance.
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		listeners: make(map[string][]EventListener),
	}
}

// RegisterListener registers an event listener for a specific event type.
func (ed *EventDispatcher) RegisterListener(eventType string, listener EventListener) {
	if _, ok := ed.listeners[eventType]; !ok {
		ed.listeners[eventType] = []EventListener{}
	}
	ed.listeners[eventType] = append(ed.listeners[eventType], listener)
}

// UnregisterListener unregisters an event listener for a specific event type.
func (ed *EventDispatcher) UnregisterListener(eventType string, listener EventListener) error {
	if _, ok := ed.listeners[eventType]; !ok {
		return errors.New("no listeners registered for this event type")
	}

	for i, l := range ed.listeners[eventType] {
		if l == listener {
			ed.listeners[eventType] = append(ed.listeners[eventType][:i], ed.listeners[eventType][i+1:]...)
			return nil
		}
	}
	return errors.New("listener not found")
}

// DispatchEvent dispatches an event to all registered listeners.
func (ed *EventDispatcher) DispatchEvent(event Event) {
	if listeners, ok := ed.listeners[event.Type]; ok {
		for _, listener := range listeners {
			go listener.HandleEvent(event)
		}
	}
}

// Utility functions for event ID generation, encryption, and decryption

// generateEventID generates a unique event ID.
func generateEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// generateEncryptionKey generates a secure encryption key.
func generateEncryptionKey() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey([]byte("passphrase"), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(key)
}

// encrypt encrypts data using AES-GCM with the provided passphrase.
func encrypt(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES-GCM with the provided passphrase.
func decrypt(encryptedData, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Specific Event Listeners for SYN130 Token Standard

// OwnershipChangeListener listens for ownership change events.
type OwnershipChangeListener struct{}

// HandleEvent handles ownership change events.
func (ocl *OwnershipChangeListener) HandleEvent(event Event) error {
	// Implement the business logic for handling ownership change events.
	// Example: updating the ownership records in the blockchain ledger.
	fmt.Printf("Handling ownership change event: %v\n", event)
	return nil
}

// AssetValuationChangeListener listens for asset valuation change events.
type AssetValuationChangeListener struct{}

// HandleEvent handles asset valuation change events.
func (avcl *AssetValuationChangeListener) HandleEvent(event Event) error {
	// Implement the business logic for handling asset valuation change events.
	// Example: updating the valuation records and notifying stakeholders.
	fmt.Printf("Handling asset valuation change event: %v\n", event)
	return nil
}

// LeaseExpirationListener listens for lease expiration events.
type LeaseExpirationListener struct{}

// HandleEvent handles lease expiration events.
func (lel *LeaseExpirationListener) HandleEvent(event Event) error {
	// Implement the business logic for handling lease expiration events.
	// Example: sending notifications to lessors and lessees and updating lease status.
	fmt.Printf("Handling lease expiration event: %v\n", event)
	return nil
}

// Syn130EventListenerSystem is responsible for managing and dispatching events specific to the SYN130 Token Standard.
type Syn130EventListenerSystem struct {
	dispatcher *EventDispatcher
}

// NewSyn130EventListenerSystem creates a new Syn130EventListenerSystem instance.
func NewSyn130EventListenerSystem() *Syn130EventListenerSystem {
	return &Syn130EventListenerSystem{
		dispatcher: NewEventDispatcher(),
	}
}

// RegisterStandardListeners registers standard listeners for the SYN130 Token Standard.
func (sels *Syn130EventListenerSystem) RegisterStandardListeners() {
	ownershipChangeListener := &OwnershipChangeListener{}
	assetValuationChangeListener := &AssetValuationChangeListener{}
	leaseExpirationListener := &LeaseExpirationListener{}

	sels.dispatcher.RegisterListener("ownership_change", ownershipChangeListener)
	sels.dispatcher.RegisterListener("valuation_change", assetValuationChangeListener)
	sels.dispatcher.RegisterListener("lease_expiration", leaseExpirationListener)
}

// DispatchSyn130Event dispatches an event specific to the SYN130 Token Standard.
func (sels *Syn130EventListenerSystem) DispatchSyn130Event(eventType string, data map[string]interface{}) {
	event := Event{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}
	sels.dispatcher.DispatchEvent(event)
}

// LoggingEventListener logs all events for auditing purposes.
type LoggingEventListener struct{}

// HandleEvent logs the event details.
func (lel *LoggingEventListener) HandleEvent(event Event) error {
	fmt.Printf("Event logged: ID=%s, Type=%s, Timestamp=%d, Data=%v\n",
		event.ID, event.Type, event.Timestamp, event.Data)
	return nil
}

// Example of integrating a logging listener into the event system.
func (sels *Syn130EventListenerSystem) RegisterLoggingListener() {
	loggingEventListener := &LoggingEventListener{}
	sels.dispatcher.RegisterListener("ownership_change", loggingEventListener)
	sels.dispatcher.RegisterListener("valuation_change", loggingEventListener)
	sels.dispatcher.RegisterListener("lease_expiration", loggingEventListener)
}
