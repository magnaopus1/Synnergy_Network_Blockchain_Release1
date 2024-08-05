package security

import (
	"errors"
	"sync"
)

// AccessControlManager manages role-based access control for SYN223 token operations.
type AccessControlManager struct {
	mu            sync.RWMutex
	roles         map[string]map[string]bool // role -> addresses
	roleHierarchy map[string][]string        // role -> subroles
}

// NewAccessControlManager initializes a new AccessControlManager instance.
func NewAccessControlManager() *AccessControlManager {
	return &AccessControlManager{
		roles:         make(map[string]map[string]bool),
		roleHierarchy: make(map[string][]string),
	}
}

// AddRole adds a new role to the access control manager.
func (acm *AccessControlManager) AddRole(role string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.roles[role]; exists {
		return errors.New("role already exists")
	}

	acm.roles[role] = make(map[string]bool)
	return nil
}

// RemoveRole removes a role from the access control manager.
func (acm *AccessControlManager) RemoveRole(role string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.roles[role]; !exists {
		return errors.New("role not found")
	}

	delete(acm.roles, role)
	delete(acm.roleHierarchy, role)
	return nil
}

// AssignRole assigns a role to an address.
func (acm *AccessControlManager) AssignRole(role, address string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.roles[role]; !exists {
		return errors.New("role not found")
	}

	acm.roles[role][address] = true
	return nil
}

// RevokeRole revokes a role from an address.
func (acm *AccessControlManager) RevokeRole(role, address string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.roles[role]; !exists {
		return errors.New("role not found")
	}

	delete(acm.roles[role], address)
	return nil
}

// HasRole checks if an address has a specific role.
func (acm *AccessControlManager) HasRole(role, address string) bool {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	if _, exists := acm.roles[role]; !exists {
		return false
	}

	return acm.roles[role][address]
}

// DefineRoleHierarchy defines the hierarchy of roles.
func (acm *AccessControlManager) DefineRoleHierarchy(role string, subroles []string) error {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	if _, exists := acm.roles[role]; !exists {
		return errors.New("role not found")
	}

	for _, subrole := range subroles {
		if _, exists := acm.roles[subrole]; !exists {
			return errors.New("subrole not found: " + subrole)
		}
	}

	acm.roleHierarchy[role] = subroles
	return nil
}

// IsAuthorized checks if an address is authorized for a specific role or any of its subroles.
func (acm *AccessControlManager) IsAuthorized(role, address string) bool {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	if acm.roles[role][address] {
		return true
	}

	subroles, exists := acm.roleHierarchy[role]
	if !exists {
		return false
	}

	for _, subrole := range subroles {
		if acm.roles[subrole][address] {
			return true
		}
	}

	return false
}

// ListRoles lists all roles in the access control manager.
func (acm *AccessControlManager) ListRoles() []string {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	var roles []string
	for role := range acm.roles {
		roles = append(roles, role)
	}

	return roles
}

// ListAddressesByRole lists all addresses assigned to a specific role.
func (acm *AccessControlManager) ListAddressesByRole(role string) ([]string, error) {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	if _, exists := acm.roles[role]; !exists {
		return nil, errors.New("role not found")
	}

	var addresses []string
	for address := range acm.roles[role] {
		addresses = append(addresses, address)
	}

	return addresses, nil
}

// EncryptRoleData encrypts role data using a specified encryption technique.
func (acm *AccessControlManager) EncryptRoleData(role string, passphrase string) (string, error) {
	acm.mu.RLock()
	defer acm.mu.RUnlock()

	roleData, exists := acm.roles[role]
	if !exists {
		return "", errors.New("role not found")
	}

	// Serialize role data to JSON
	jsonData, err := utils.ToJSON(roleData)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptRoleData decrypts role data using a specified decryption technique.
func (acm *AccessControlManager) DecryptRoleData(encryptedData, passphrase string) (map[string]bool, error) {
	acm.mu.Lock()
	defer acm.mu.Unlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	// Deserialize JSON data to role data
	var roleData map[string]bool
	err = utils.FromJSON(decryptedData, &roleData)
	if err != nil {
		return nil, err
	}

	return roleData, nil
}
