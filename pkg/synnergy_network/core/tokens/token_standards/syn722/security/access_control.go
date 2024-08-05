package security

import (
	"errors"
	"sync"
)

// Role constants
const (
	OwnerRole        = "owner"
	AdminRole        = "admin"
	ViewerRole       = "viewer"
	AuthorizedRole   = "authorized"
)

// Permission defines the access permissions for each role.
type Permission struct {
	CanTransfer bool
	CanUpdateMetadata bool
	CanSwitchMode bool
	CanSetRoyalty bool
	CanLogEvent bool
}

// RolePermissions maps roles to their permissions.
var RolePermissions = map[string]Permission{
	OwnerRole: {
		CanTransfer:       true,
		CanUpdateMetadata: true,
		CanSwitchMode:     true,
		CanSetRoyalty:     true,
		CanLogEvent:       true,
	},
	AdminRole: {
		CanTransfer:       false,
		CanUpdateMetadata: true,
		CanSwitchMode:     true,
		CanSetRoyalty:     false,
		CanLogEvent:       true,
	},
	ViewerRole: {
		CanTransfer:       false,
		CanUpdateMetadata: false,
		CanSwitchMode:     false,
		CanSetRoyalty:     false,
		CanLogEvent:       false,
	},
	AuthorizedRole: {
		CanTransfer:       true,
		CanUpdateMetadata: true,
		CanSwitchMode:     true,
		CanSetRoyalty:     true,
		CanLogEvent:       true,
	},
}

// AccessControl manages access permissions for SYN722 tokens.
type AccessControl struct {
	mu          sync.Mutex
	TokenRoles  map[string]map[string]string // tokenID -> userID -> role
}

// NewAccessControl creates a new instance of AccessControl.
func NewAccessControl() *AccessControl {
	return &AccessControl{
		TokenRoles: make(map[string]map[string]string),
	}
}

// AssignRole assigns a role to a user for a specific token.
func (ac *AccessControl) AssignRole(tokenID, userID, role string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := RolePermissions[role]; !exists {
		return errors.New("invalid role")
	}

	if _, exists := ac.TokenRoles[tokenID]; !exists {
		ac.TokenRoles[tokenID] = make(map[string]string)
	}

	ac.TokenRoles[tokenID][userID] = role
	return nil
}

// RemoveRole removes a role from a user for a specific token.
func (ac *AccessControl) RemoveRole(tokenID, userID string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.TokenRoles[tokenID]; !exists {
		return errors.New("tokenID not found")
	}

	if _, exists := ac.TokenRoles[tokenID][userID]; !exists {
		return errors.New("userID not found")
	}

	delete(ac.TokenRoles[tokenID], userID)
	return nil
}

// GetRole retrieves the role of a user for a specific token.
func (ac *AccessControl) GetRole(tokenID, userID string) (string, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if roles, exists := ac.TokenRoles[tokenID]; exists {
		if role, exists := roles[userID]; exists {
			return role, nil
		}
	}

	return "", errors.New("role not found")
}

// CheckPermission checks if a user has a specific permission for a token.
func (ac *AccessControl) CheckPermission(tokenID, userID, permission string) (bool, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	role, err := ac.GetRole(tokenID, userID)
	if err != nil {
		return false, err
	}

	switch permission {
	case "CanTransfer":
		return RolePermissions[role].CanTransfer, nil
	case "CanUpdateMetadata":
		return RolePermissions[role].CanUpdateMetadata, nil
	case "CanSwitchMode":
		return RolePermissions[role].CanSwitchMode, nil
	case "CanSetRoyalty":
		return RolePermissions[role].CanSetRoyalty, nil
	case "CanLogEvent":
		return RolePermissions[role].CanLogEvent, nil
	default:
		return false, errors.New("invalid permission")
	}
}

// AuthorizeAction checks if a user is authorized to perform a specific action on a token.
func (ac *AccessControl) AuthorizeAction(tokenID, userID, action string) error {
	isAuthorized, err := ac.CheckPermission(tokenID, userID, action)
	if err != nil {
		return err
	}

	if !isAuthorized {
		return errors.New("user is not authorized to perform this action")
	}

	return nil
}
