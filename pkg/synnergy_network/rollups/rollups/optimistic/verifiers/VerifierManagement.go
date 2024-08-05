package verifiers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Verifier represents a node in the decentralized verifier network.
type Verifier struct {
	ID        string
	PublicKey string
	JoinedAt  time.Time
	LastSeen  time.Time
}

// VerifierManagement manages the decentralized network of verifiers.
type VerifierManagement struct {
	mu        sync.Mutex
	verifiers map[string]*Verifier
}

// NewVerifierManagement initializes a new VerifierManagement instance.
func NewVerifierManagement() *VerifierManagement {
	return &VerifierManagement{
		verifiers: make(map[string]*Verifier),
	}
}

// RegisterVerifier registers a new verifier node in the network.
func (vm *VerifierManagement) RegisterVerifier(publicKey string) (string, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	id := generateVerifierID(publicKey)
	if _, exists := vm.verifiers[id]; exists {
		return "", errors.New("verifier already registered")
	}

	verifier := &Verifier{
		ID:        id,
		PublicKey: publicKey,
		JoinedAt:  time.Now(),
		LastSeen:  time.Now(),
	}

	vm.verifiers[id] = verifier
	return id, nil
}

// GetVerifier retrieves a verifier by its ID.
func (vm *VerifierManagement) GetVerifier(id string) (*Verifier, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	verifier, exists := vm.verifiers[id]
	if !exists {
		return nil, errors.New("verifier not found")
	}

	return verifier, nil
}

// ListVerifiers lists all verifiers in the network.
func (vm *VerifierManagement) ListVerifiers() []*Verifier {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	var verifierList []*Verifier
	for _, verifier := range vm.verifiers {
		verifierList = append(verifierList, verifier)
	}

	return verifierList
}

// UpdateVerifierHeartbeat updates the last seen time of a verifier.
func (vm *VerifierManagement) UpdateVerifierHeartbeat(id string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	verifier, exists := vm.verifiers[id]
	if !exists {
		return errors.New("verifier not found")
	}

	verifier.LastSeen = time.Now()
	return nil
}

// RemoveInactiveVerifiers removes verifiers that have been inactive for a specified duration.
func (vm *VerifierManagement) RemoveInactiveVerifiers(inactiveDuration time.Duration) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	currentTime := time.Now()
	for id, verifier := range vm.verifiers {
		if currentTime.Sub(verifier.LastSeen) > inactiveDuration {
			delete(vm.verifiers, id)
		}
	}
}

// generateVerifierID generates a unique verifier ID using Argon2.
func generateVerifierID(publicKey string) string {
	salt := []byte("unique_salt")
	hash := argon2.IDKey([]byte(publicKey), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// ExportVerifierMetrics exports metrics about the verifiers for monitoring tools.
func (vm *VerifierManagement) ExportVerifierMetrics() map[string]interface{} {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	totalVerifiers := len(vm.verifiers)
	activeVerifiers := 0
	inactiveVerifiers := 0
	for _, verifier := range vm.verifiers {
		if time.Since(verifier.LastSeen) < 5*time.Minute {
			activeVerifiers++
		} else {
			inactiveVerifiers++
		}
	}

	metrics := map[string]interface{}{
		"totalVerifiers":    totalVerifiers,
		"activeVerifiers":   activeVerifiers,
		"inactiveVerifiers": inactiveVerifiers,
	}

	return metrics
}

// PrintVerifierList prints the list of verifiers.
func (vm *VerifierManagement) PrintVerifierList() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	fmt.Println("List of Verifiers:")
	for _, verifier := range vm.verifiers {
		fmt.Printf("ID: %s, PublicKey: %s, JoinedAt: %s, LastSeen: %s\n",
			verifier.ID, verifier.PublicKey, verifier.JoinedAt.String(), verifier.LastSeen.String())
	}
}
