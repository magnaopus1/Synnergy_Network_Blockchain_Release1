package health_performance_dashboards

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Role defines the role structure
type Role struct {
	Name        string
	Permissions []string
}

// NodeType defines the node type structure
type NodeType struct {
	Type string
	Role Role
}

// RoleBasedAccessControl manages the RBAC for different node types
type RoleBasedAccessControl struct {
	roles     map[string]Role
	nodeTypes map[string]NodeType
	mutex     sync.Mutex
}

// NewRBAC initializes a new RoleBasedAccessControl
func NewRBAC() *RoleBasedAccessControl {
	return &RoleBasedAccessControl{
		roles:     make(map[string]Role),
		nodeTypes: make(map[string]NodeType),
	}
}

// AddRole adds a new role to the RBAC
func (rbac *RoleBasedAccessControl) AddRole(name string, permissions []string) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	rbac.roles[name] = Role{Name: name, Permissions: permissions}
}

// AssignRole assigns a role to a node type
func (rbac *RoleBasedAccessControl) AssignRole(nodeType string, roleName string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	role, exists := rbac.roles[roleName]
	if !exists {
		return fmt.Errorf("role %s does not exist", roleName)
	}

	rbac.nodeTypes[nodeType] = NodeType{Type: nodeType, Role: role}
	return nil
}

// GetRolePermissions retrieves the permissions for a given node type
func (rbac *RoleBasedAccessControl) GetRolePermissions(nodeType string) ([]string, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	node, exists := rbac.nodeTypes[nodeType]
	if !exists {
		return nil, fmt.Errorf("node type %s does not exist", nodeType)
	}

	return node.Role.Permissions, nil
}

// EncryptData encrypts the given data using AES encryption
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts the given data using AES encryption
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// SaveRBACToFile saves the RBAC configuration to a file
func (rbac *RoleBasedAccessControl) SaveRBACToFile(filename string, passphrase string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	data, err := json.Marshal(rbac)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encryptedData, 0644)
}

// LoadRBACFromFile loads the RBAC configuration from a file
func (rbac *RoleBasedAccessControl) LoadRBACFromFile(filename string, passphrase string) error {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	data, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return err
	}

	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	return json.Unmarshal(data, rbac)
}

func main() {
	rbac := NewRBAC()

	// Add roles
	rbac.AddRole("AllOtherNodes", []string{"read", "write"})
	rbac.AddRole("ElectedAuthorityNode", []string{"read", "write", "manage"})
	rbac.AddRole("AuthorityNode", []string{"read", "write", "manage"})
	rbac.AddRole("CreditorNode", []string{"read", "write", "credit"})
	rbac.AddRole("MilitaryNode", []string{"read", "write", "secure"})
	rbac.AddRole("BankingNode", []string{"read", "write", "finance"})
	rbac.AddRole("GovernmentNode", []string{"read", "write", "regulate"})
	rbac.AddRole("CentralBankingNode", []string{"read", "write", "monetary_policy"})

	// Assign roles to node types
	rbac.AssignRole("generic_node", "AllOtherNodes")
	rbac.AssignRole("elected_authority", "ElectedAuthorityNode")
	rbac.AssignRole("authority", "AuthorityNode")
	rbac.AssignRole("creditor", "CreditorNode")
	rbac.AssignRole("military", "MilitaryNode")
	rbac.AssignRole("banking", "BankingNode")
	rbac.AssignRole("government", "GovernmentNode")
	rbac.AssignRole("central_banking", "CentralBankingNode")

	// Save RBAC configuration to file
	passphrase := "strongpassphrase"
	if err := rbac.SaveRBACToFile("rbac_config.json", passphrase); err != nil {
		fmt.Printf("Error saving RBAC to file: %v\n", err)
	}

	// Load RBAC configuration from file
	newRBAC := NewRBAC()
	if err := newRBAC.LoadRBACFromFile("rbac_config.json", passphrase); err != nil {
		fmt.Printf("Error loading RBAC from file: %v\n", err)
	}

	// Get role permissions for a node type
	permissions, err := newRBAC.GetRolePermissions("banking")
	if err != nil {
		fmt.Printf("Error getting permissions: %v\n", err)
	} else {
		fmt.Printf("Permissions for banking node: %v\n", permissions)
	}
}
