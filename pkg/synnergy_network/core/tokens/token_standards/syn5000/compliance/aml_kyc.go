// aml_kyc.go

package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// User represents a user in the system with KYC information
type User struct {
	UserID        string    // Unique identifier for the user
	Name          string    // Full name of the user
	Email         string    // Email address of the user
	Verified      bool      // Verification status of the user
	KYCStatus     string    // KYC status (pending/verified/rejected)
	VerificationDate time.Time // Date when KYC was verified
	Documents     []string  // List of document IDs for verification
	SecureHash    string    // Secure hash for verifying user integrity
}

// KYCStatus constants
const (
	KYCStatusPending   = "pending"
	KYCStatusVerified  = "verified"
	KYCStatusRejected  = "rejected"
)

// AMLKYCManager manages AML and KYC processes
type AMLKYCManager struct {
	mu    sync.RWMutex
	users map[string]*User // In-memory storage of users
}

// NewAMLKYCManager creates a new instance of AMLKYCManager
func NewAMLKYCManager() *AMLKYCManager {
	return &AMLKYCManager{
		users: make(map[string]*User),
	}
}

// RegisterUser registers a new user and initiates the KYC process
func (manager *AMLKYCManager) RegisterUser(name, email string, documents []string) (*User, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// Generate unique UserID and secure hash
	userID := generateUniqueID()
	secureHash := generateUserSecureHash(userID, name, email, documents)

	// Create the User instance
	user := &User{
		UserID:        userID,
		Name:          name,
		Email:         email,
		Verified:      false,
		KYCStatus:     KYCStatusPending,
		VerificationDate: time.Time{},
		Documents:     documents,
		SecureHash:    secureHash,
	}

	// Store the user
	manager.users[userID] = user

	return user, nil
}

// VerifyUser verifies a user's identity based on their KYC documents
func (manager *AMLKYCManager) VerifyUser(userID string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	user, exists := manager.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if user.KYCStatus != KYCStatusPending {
		return errors.New("user KYC status is not pending")
	}

	// Simulate document verification process
	// In a real-world scenario, this would involve interaction with a KYC provider
	if len(user.Documents) == 0 {
		return errors.New("no documents provided for verification")
	}

	// Mark the user as verified
	user.Verified = true
	user.KYCStatus = KYCStatusVerified
	user.VerificationDate = time.Now()
	user.SecureHash = generateUserSecureHash(user.UserID, user.Name, user.Email, user.Documents)

	// Update the user in storage
	manager.users[userID] = user

	return nil
}

// RejectUser rejects a user's KYC verification
func (manager *AMLKYCManager) RejectUser(userID string, reason string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	user, exists := manager.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if user.KYCStatus != KYCStatusPending {
		return errors.New("user KYC status is not pending")
	}

	// Mark the user as rejected
	user.Verified = false
	user.KYCStatus = KYCStatusRejected
	user.SecureHash = generateUserSecureHash(user.UserID, user.Name, user.Email, user.Documents)

	// Update the user in storage
	manager.users[userID] = user

	return nil
}

// GetUser retrieves a user's details by their ID
func (manager *AMLKYCManager) GetUser(userID string) (*User, error) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	user, exists := manager.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// generateUniqueID generates a unique identifier for users using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateUserSecureHash generates a secure hash for user verification
func generateUserSecureHash(userID, name, email string, documents []string) string {
	hash := sha256.New()
	hash.Write([]byte(userID))
	hash.Write([]byte(name))
	hash.Write([]byte(email))
	for _, doc := range documents {
		hash.Write([]byte(doc))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
