package security

import (
	"errors"
	"sync"
)

// Role constants
const (
	RoleAdmin       = "admin"
	RoleUser        = "user"
	RoleViewer      = "viewer"
)

// Permissions define the actions available for each role
var Permissions = map[string][]string{
	RoleAdmin: {
		"register_user",
		"remove_user",
		"update_user",
		"transfer_tokens",
		"peg_tokens",
		"redeem_tokens",
		"get_commodity_price",
		"list_commodities",
	},
	RoleUser: {
		"transfer_tokens",
		"peg_tokens",
		"redeem_tokens",
		"get_commodity_price",
		"list_commodities",
	},
	RoleViewer: {
		"get_commodity_price",
		"list_commodities",
	},
}

// AccessControlManager handles role-based access control
type AccessControlManager struct {
	mu       sync.RWMutex
	userRoles map[string]string
}

// NewAccessControlManager creates a new access control manager
func NewAccessControlManager() *AccessControlManager {
	return &AccessControlManager{
		userRoles: make(map[string]string),
	}
}

// AssignRole assigns a role to a user
func (acm *AccessControlManager) AssignRole(userID, role string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := Permissions[role]; !exists {
		return errors.New("invalid role")
	}

	acm.userRoles[userID] = role
	return nil
}

// RevokeRole revokes a role from a user
func (acm *AccessControlManager) RevokeRole(userID string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.userRoles[userID]; !exists {
		return errors.New("user does not have a role assigned")
	}

	delete(acm.userRoles, userID)
	return nil
}

// UpdateRole updates the role of a user
func (acm *AccessControlManager) UpdateRole(userID, role string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := Permissions[role]; !exists {
		return errors.New("invalid role")
	}

	acm.userRoles[userID] = role
	return nil
}

// CheckPermission checks if a user has permission to perform an action
func (acm *AccessControlManager) CheckPermission(userID, action string) error {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	role, exists := acm.userRoles[userID]
	if !exists {
		return errors.New("user does not have a role assigned")
	}

	allowedActions, exists := Permissions[role]
	if !exists {
		return errors.New("role has no permissions assigned")
	}

	for _, allowedAction := range allowedActions {
		if allowedAction == action {
			return nil
		}
	}

	return errors.New("user does not have permission to perform this action")
}

// GetRole retrieves the role of a user
func (acm *AccessControlManager) GetRole(userID string) (string, error) {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	role, exists := acm.userRoles[userID]
	if !exists {
		return "", errors.New("user does not have a role assigned")
	}

	return role, nil
}

// ListRoles lists all roles and their permissions
func (acm *AccessControlManager) ListRoles() map[string][]string {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	roles := make(map[string][]string)
	for role, actions := range Permissions {
		roles[role] = actions
	}

	return roles
}
