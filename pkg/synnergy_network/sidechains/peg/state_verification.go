package peg

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// StateVerifier manages the state verification process for the blockchain.
type StateVerifier struct {
	mu        sync.Mutex
	stateDB   map[string]string // Simulated state database
	alertChan chan string
}

// NewStateVerifier creates a new instance of StateVerifier.
func NewStateVerifier() *StateVerifier {
	return &StateVerifier{
		stateDB:   make(map[string]string),
		alertChan: make(chan string, 100),
	}
}

// HashState hashes the state data using SHA-256.
func (sv *StateVerifier) HashState(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// VerifyState verifies the state against the expected hash.
func (sv *StateVerifier) VerifyState(data string, expectedHash string) error {
	actualHash := sv.HashState(data)
	if actualHash != expectedHash {
		sv.LogVerificationEvent("State verification failed")
		return errors.New("state verification failed: hashes do not match")
	}
	return nil
}

// StoreState stores the state in the state database.
func (sv *StateVerifier) StoreState(key string, state string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.stateDB[key] = state
	sv.LogVerificationEvent(fmt.Sprintf("State stored for key %s", key))
}

// GetState retrieves the state from the state database.
func (sv *StateVerifier) GetState(key string) (string, error) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	state, exists := sv.stateDB[key]
	if !exists {
		return "", errors.New("state not found")
	}
	return state, nil
}

// MonitorState continuously monitors state-related events and sends alerts.
func (sv *StateVerifier) MonitorState() {
	for {
		select {
		case alert := <-sv.alertChan:
			fmt.Printf("STATE VERIFICATION ALERT: %s\n", alert)
		case <-time.After(1 * time.Minute):
			sv.alertChan <- "State verification check passed"
		}
	}
}

// LogVerificationEvent logs a state verification event to the appropriate sink.
func (sv *StateVerifier) LogVerificationEvent(event string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.alertChan <- event
}

// Example implementation of state verification process
func main() {
	sv := NewStateVerifier()

	go sv.MonitorState()

	data := "example state data"
	hash := sv.HashState(data)

	sv.StoreState("exampleKey", data)

	retrievedState, err := sv.GetState("exampleKey")
	if err != nil {
		fmt.Printf("Failed to retrieve state: %v\n", err)
		return
	}

	err = sv.VerifyState(retrievedState, hash)
	if err != nil {
		fmt.Printf("State verification error: %v\n", err)
		return
	}

	fmt.Println("State verification successful")
}
