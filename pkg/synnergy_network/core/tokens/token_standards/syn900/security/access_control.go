package security

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"
)

// UserRole defines different roles in the access control system
type UserRole int

const (
	Admin UserRole = iota
	Verifier
	User
)

// AccessControl manages the access control mechanisms
type AccessControl struct {
	roles     map[string]UserRole
	tokens    map[string]string
	tokenTTL  time.Duration
	saltSize  int
	hashFuncs map[UserRole]func(string) string
}

// NewAccessControl initializes a new AccessControl system
func NewAccessControl(tokenTTL time.Duration, saltSize int) *AccessControl {
	return &AccessControl{
		roles:    make(map[string]UserRole),
		tokens:   make(map[string]string),
		tokenTTL: tokenTTL,
		saltSize: saltSize,
		hashFuncs: map[UserRole]func(string) string{
			Admin:    hashAdminPassword,
			Verifier: hashVerifierPassword,
			User:     hashUserPassword,
		},
	}
}

// AddUser adds a new user with a specified role
func (ac *AccessControl) AddUser(username string, role UserRole, password string) error {
	if _, exists := ac.roles[username]; exists {
		return errors.New("user already exists")
	}
	ac.roles[username] = role
	ac.tokens[username] = ac.hashFuncs[role](password)
	return nil
}

// Authenticate authenticates a user with a username and password
func (ac *AccessControl) Authenticate(username string, password string) (string, error) {
	hashedPassword, exists := ac.tokens[username]
	if !exists || hashedPassword != ac.hashFuncs[ac.roles[username]](password) {
		return "", errors.New("authentication failed")
	}

	token, err := generateToken(ac.saltSize)
	if err != nil {
		return "", err
	}
	ac.tokens[token] = username

	go ac.expireToken(token)
	return token, nil
}

// Authorize checks if a token is valid and returns the user's role
func (ac *AccessControl) Authorize(token string) (UserRole, error) {
	username, exists := ac.tokens[token]
	if !exists {
		return -1, errors.New("unauthorized")
	}
	return ac.roles[username], nil
}

// ChangeUserRole changes the role of an existing user
func (ac *AccessControl) ChangeUserRole(username string, newRole UserRole) error {
	if _, exists := ac.roles[username]; !exists {
		return errors.New("user not found")
	}
	ac.roles[username] = newRole
	return nil
}

// RevokeUser revokes a user's access
func (ac *AccessControl) RevokeUser(username string) error {
	if _, exists := ac.roles[username]; !exists {
		return errors.New("user not found")
	}
	delete(ac.roles, username)
	delete(ac.tokens, username)
	return nil
}

// generateToken generates a random token
func generateToken(saltSize int) (string, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(salt), nil
}

// expireToken invalidates a token after the TTL
func (ac *AccessControl) expireToken(token string) {
	time.Sleep(ac.tokenTTL)
	delete(ac.tokens, token)
}

// hashAdminPassword hashes a password using Argon2 for admin users
func hashAdminPassword(password string) string {
	return hashPassword(password, 4, 32*1024, 4, 32)
}

// hashVerifierPassword hashes a password using Argon2 for verifier users
func hashVerifierPassword(password string) string {
	return hashPassword(password, 3, 16*1024, 3, 32)
}

// hashUserPassword hashes a password using Argon2 for regular users
func hashUserPassword(password string) string {
	return hashPassword(password, 2, 8*1024, 2, 32)
}

// hashPassword hashes a password using Argon2
func hashPassword(password string, time, memory uint32, threads uint8, keyLen uint32) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	return base64.RawStdEncoding.EncodeToString(hash)
}
