package security

import (
	"fmt"
	"sync"
	"time"
)

// Role constants
const (
	RoleOwner       = "Owner"
	RoleAdmin       = "Admin"
	RoleMinter      = "Minter"
	RoleBurner      = "Burner"
	RoleViewer      = "Viewer"
	RoleAuctioneer  = "Auctioneer"
)

// AccessControlEntry represents an entry in the access control list
type AccessControlEntry struct {
	UserID    string
	Role      string
	GrantedAt time.Time
	GrantedBy string
}

// AccessControlManager manages the access control for SYN721 tokens
type AccessControlManager struct {
	accessList map[string][]AccessControlEntry
	mutex      sync.Mutex
}

// NewAccessControlManager initializes a new AccessControlManager
func NewAccessControlManager() *AccessControlManager {
	return &AccessControlManager{
		accessList: make(map[string][]AccessControlEntry),
	}
}

// GrantRole grants a specific role to a user for a token
func (acm *AccessControlManager) GrantRole(tokenID, userID, role, grantedBy string) error {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	entry := AccessControlEntry{
		UserID:    userID,
		Role:      role,
		GrantedAt: time.Now(),
		GrantedBy: grantedBy,
	}

	acm.accessList[tokenID] = append(acm.accessList[tokenID], entry)
	return nil
}

// RevokeRole revokes a specific role from a user for a token
func (acm *AccessControlManager) RevokeRole(tokenID, userID, role string) error {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	entries, exists := acm.accessList[tokenID]
	if !exists {
		return fmt.Errorf("no access control entries found for token ID %s", tokenID)
	}

	var updatedEntries []AccessControlEntry
	for _, entry := range entries {
		if !(entry.UserID == userID && entry.Role == role) {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	acm.accessList[tokenID] = updatedEntries
	return nil
}

// HasRole checks if a user has a specific role for a token
func (acm *AccessControlManager) HasRole(tokenID, userID, role string) bool {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	entries, exists := acm.accessList[tokenID]
	if !exists {
		return false
	}

	for _, entry := range entries {
		if entry.UserID == userID && entry.Role == role {
			return true
		}
	}

	return false
}

// GetRoles retrieves all roles assigned to a user for a token
func (acm *AccessControlManager) GetRoles(tokenID, userID string) []string {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	var roles []string
	entries, exists := acm.accessList[tokenID]
	if !exists {
		return roles
	}

	for _, entry := range entries {
		if entry.UserID == userID {
			roles = append(roles, entry.Role)
		}
	}

	return roles
}

// ListAccessControlEntries lists all access control entries for a token
func (acm *AccessControlManager) ListAccessControlEntries(tokenID string) ([]AccessControlEntry, error) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	entries, exists := acm.accessList[tokenID]
	if !exists {
		return nil, fmt.Errorf("no access control entries found for token ID %s", tokenID)
	}

	return entries, nil
}

// ListTokensByUser lists all tokens a user has roles for
func (acm *AccessControlManager) ListTokensByUser(userID string) []string {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	tokenIDs := make(map[string]bool)
	for tokenID, entries := range acm.accessList {
		for _, entry := range entries {
			if entry.UserID == userID {
				tokenIDs[tokenID] = true
			}
		}
	}

	var result []string
	for tokenID := range tokenIDs {
		result = append(result, tokenID)
	}

	return result
}
