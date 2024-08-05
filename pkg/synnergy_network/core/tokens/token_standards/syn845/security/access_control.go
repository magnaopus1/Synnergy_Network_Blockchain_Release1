package security

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/core/security"
)

// RoleType represents different roles in the system
type RoleType string

const (
	Owner       RoleType = "owner"
	Administrator RoleType = "administrator"
	Borrower    RoleType = "borrower"
)

// AccessControlEntry represents an access control entry for a user
type AccessControlEntry struct {
	UserID    string    `json:"user_id"`
	Role      RoleType  `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AccessControl manages access control entries and permissions
type AccessControl struct {
	mu sync.Mutex
	entries map[string]AccessControlEntry
}

// NewAccessControl creates a new instance of AccessControl
func NewAccessControl() *AccessControl {
	return &AccessControl{
		entries: make(map[string]AccessControlEntry),
	}
}

// GrantAccess grants a role to a user with an optional expiration time
func (ac *AccessControl) GrantAccess(userID string, role RoleType, expiresAt *time.Time) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry := AccessControlEntry{
		UserID:    userID,
		Role:      role,
		ExpiresAt: time.Time{},
	}

	if expiresAt != nil {
		entry.ExpiresAt = *expiresAt
	}

	ac.entries[userID] = entry
	return saveAccessControlEntryToStorage(entry)
}

// RevokeAccess revokes a role from a user
func (ac *AccessControl) RevokeAccess(userID string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.entries[userID]; !exists {
		return errors.New("access control entry not found")
	}

	delete(ac.entries, userID)
	return deleteAccessControlEntryFromStorage(userID)
}

// CheckAccess checks if a user has a specific role
func (ac *AccessControl) CheckAccess(userID string, role RoleType) (bool, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry, exists := ac.entries[userID]
	if !exists {
		return false, errors.New("access control entry not found")
	}

	if entry.Role != role {
		return false, nil
	}

	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		delete(ac.entries, userID)
		return false, errors.New("access control entry has expired")
	}

	return true, nil
}

// getAccessControlEntry retrieves an access control entry by user ID
func (ac *AccessControl) getAccessControlEntry(userID string) (AccessControlEntry, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	entry, exists := ac.entries[userID]
	if !exists {
		return AccessControlEntry{}, errors.New("access control entry not found")
	}

	return entry, nil
}

// saveAccessControlEntryToStorage securely stores an access control entry
func saveAccessControlEntryToStorage(entry AccessControlEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("accessControlEntry", entry.UserID, encryptedData)
}

// deleteAccessControlEntryFromStorage deletes an access control entry from storage
func deleteAccessControlEntryFromStorage(userID string) error {
	return storage.Delete("accessControlEntry", userID)
}
