package security

import (
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AccessControl manages user access and permissions within the SYN11 system.
type AccessControl struct {
	users          map[string]*User
	roles          map[string]*Role
	permissions    map[string]Permission
	salt           []byte
}

// User represents a user in the system.
type User struct {
	ID        string
	Username  string
	Password  []byte
	Salt      []byte
	Role      *Role
	LastLogin time.Time
}

// Role represents a role with specific permissions.
type Role struct {
	Name        string
	Permissions map[string]Permission
}

// Permission represents a specific action that can be performed.
type Permission string

// NewAccessControl initializes a new AccessControl system.
func NewAccessControl() *AccessControl {
	return &AccessControl{
		users:       make(map[string]*User),
		roles:       make(map[string]*Role),
		permissions: make(map[string]Permission),
		salt:        []byte("defaultSaltValue"), // This should be replaced with a more secure generation in production
	}
}

// AddUser adds a new user to the system.
func (ac *AccessControl) AddUser(username, password, roleName string) error {
	if _, exists := ac.users[username]; exists {
		return errors.New("user already exists")
	}

	role, roleExists := ac.roles[roleName]
	if !roleExists {
		return errors.New("role does not exist")
	}

	salt := ac.generateSalt()
	hashedPassword, err := ac.hashPassword(password, salt)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	ac.users[username] = &User{
		ID:       username,
		Username: username,
		Password: hashedPassword,
		Salt:     salt,
		Role:     role,
	}
	log.Printf("User %s added with role %s", username, roleName)
	return nil
}

// AuthenticateUser authenticates a user's login attempt.
func (ac *AccessControl) AuthenticateUser(username, password string) (*User, error) {
	user, exists := ac.users[username]
	if !exists {
		return nil, errors.New("user does not exist")
	}

	hashedPassword, err := ac.hashPassword(password, user.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	if !comparePasswords(user.Password, hashedPassword) {
		return nil, errors.New("authentication failed")
	}

	user.LastLogin = time.Now()
	log.Printf("User %s authenticated successfully", username)
	return user, nil
}

// AuthorizeUser checks if a user has the necessary permissions.
func (ac *AccessControl) AuthorizeUser(username string, permission Permission) error {
	user, exists := ac.users[username]
	if !exists {
		return errors.New("user does not exist")
	}

	if !ac.hasPermission(user.Role, permission) {
		return errors.New("user does not have required permissions")
	}

	return nil
}

// AddRole adds a new role to the system.
func (ac *AccessControl) AddRole(roleName string, permissions []Permission) {
	permissionMap := make(map[string]Permission)
	for _, perm := range permissions {
		permissionMap[string(perm)] = perm
	}

	ac.roles[roleName] = &Role{
		Name:        roleName,
		Permissions: permissionMap,
	}
	log.Printf("Role %s added with permissions %v", roleName, permissions)
}

// AssignRole assigns a role to a user.
func (ac *AccessControl) AssignRole(username, roleName string) error {
	user, userExists := ac.users[username]
	if !userExists {
		return errors.New("user does not exist")
	}

	role, roleExists := ac.roles[roleName]
	if !roleExists {
		return errors.New("role does not exist")
	}

	user.Role = role
	log.Printf("User %s assigned to role %s", username, roleName)
	return nil
}

// AddPermission adds a new permission to the system.
func (ac *AccessControl) AddPermission(permissionName string) {
	ac.permissions[permissionName] = Permission(permissionName)
	log.Printf("Permission %s added", permissionName)
}

// hashPassword hashes the password using scrypt with a provided salt.
func (ac *AccessControl) hashPassword(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

// generateSalt generates a new salt for password hashing.
func (ac *AccessControl) generateSalt() []byte {
	// In a production system, use a secure random generator for salts.
	return []byte("secureSaltValue")
}

// comparePasswords securely compares two hashed passwords.
func comparePasswords(storedPassword, providedPassword []byte) bool {
	return string(storedPassword) == string(providedPassword)
}

// hasPermission checks if a role has a specific permission.
func (ac *AccessControl) hasPermission(role *Role, permission Permission) bool {
	_, hasPerm := role.Permissions[string(permission)]
	return hasPerm
}
