// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// ensuring high-level performance, security, and real-world applicability. This user_authentication.go file
// implements the logic for user authentication within the network.

package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/scrypt"
)

// User represents a user within the blockchain network.
type User struct {
	Username     string
	PasswordHash string
	Role         string
}

// AuthenticationService manages user authentication within the network.
type AuthenticationService struct {
	users       map[string]User
	jwtSecret   []byte
	tokenExpiry time.Duration
}

// NewAuthenticationService creates a new instance of AuthenticationService.
func NewAuthenticationService(jwtSecret string, tokenExpiry time.Duration) *AuthenticationService {
	return &AuthenticationService{
		users:       make(map[string]User),
		jwtSecret:   []byte(jwtSecret),
		tokenExpiry: tokenExpiry,
	}
}

// RegisterUser registers a new user with a username and password.
func (as *AuthenticationService) RegisterUser(username, password, role string) error {
	if _, exists := as.users[username]; exists {
		return errors.New("username already exists")
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}

	as.users[username] = User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
	}
	return nil
}

// AuthenticateUser authenticates a user and returns a JWT token if successful.
func (as *AuthenticationService) AuthenticateUser(username, password string) (string, error) {
	user, exists := as.users[username]
	if !exists {
		return "", errors.New("invalid username or password")
	}

	if !verifyPassword(user.PasswordHash, password) {
		return "", errors.New("invalid username or password")
	}

	token, err := as.generateJWTToken(username, user.Role)
	if err != nil {
		return "", err
	}

	return token, nil
}

// hashPassword hashes a password using scrypt.
func hashPassword(password string) (string, error) {
	salt := []byte("a very strong salt") // Note: In real-world applications, use a unique salt per user
	dk, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]), nil
}

// verifyPassword verifies if the provided password matches the stored password hash.
func verifyPassword(passwordHash, password string) bool {
	salt := []byte("a very strong salt") // Use the same salt used in hashPassword
	dk, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return false
	}

	hash := sha256.Sum256(dk)
	return hex.EncodeToString(hash[:]) == passwordHash
}

// generateJWTToken generates a JWT token for the authenticated user.
func (as *AuthenticationService) generateJWTToken(username, role string) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(as.tokenExpiry).Unix(),
		Issuer:    username,
		Subject:   role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(as.jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// VerifyJWTToken verifies the provided JWT token and returns the username and role if valid.
func (as *AuthenticationService) VerifyJWTToken(tokenString string) (string, string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return as.jwtSecret, nil
	})

	if err != nil {
		return "", "", err
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims.Issuer, claims.Subject, nil
	}

	return "", "", errors.New("invalid token")
}
