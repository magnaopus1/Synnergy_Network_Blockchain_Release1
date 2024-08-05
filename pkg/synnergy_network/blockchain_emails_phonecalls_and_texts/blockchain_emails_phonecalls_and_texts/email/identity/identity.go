package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// User represents a user in the system
type User struct {
	Username     string
	PasswordHash string
	Salt         string
	Email        string
	PhoneNumber  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// GenerateSalt creates a new salt for hashing
func GenerateSalt() (string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// HashPassword hashes a password with a given salt
func HashPassword(password, salt string) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), 4096, sha256.Size, sha256.New)
	return hex.EncodeToString(hash)
}

// NewUser creates a new user with hashed password and salt
func NewUser(username, password, email, phoneNumber string) (*User, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	hashedPassword := HashPassword(password, salt)

	user := &User{
		Username:     username,
		PasswordHash: hashedPassword,
		Salt:         salt,
		Email:        email,
		PhoneNumber:  phoneNumber,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return user, nil
}

// AuthenticateUser checks if the provided password matches the stored hash
func AuthenticateUser(user *User, password string) bool {
	hashedPassword := HashPassword(password, user.Salt)
	return user.PasswordHash == hashedPassword
}

// UpdatePassword updates a user's password
func UpdatePassword(user *User, newPassword string) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}

	hashedPassword := HashPassword(newPassword, salt)
	user.PasswordHash = hashedPassword
	user.Salt = salt
	user.UpdatedAt = time.Now()

	return nil
}

// UpdateEmail updates a user's email
func UpdateEmail(user *User, newEmail string) {
	user.Email = newEmail
	user.UpdatedAt = time.Now()
}

// UpdatePhoneNumber updates a user's phone number
func UpdatePhoneNumber(user *User, newPhoneNumber string) {
	user.PhoneNumber = newPhoneNumber
	user.UpdatedAt = time.Now()
}

// VerifyEmail sends a verification email to the user
func VerifyEmail(user *User) error {
	// Simulate email sending
	fmt.Printf("Verification email sent to %s\n", user.Email)
	return nil
}

// VerifyPhoneNumber sends a verification SMS to the user
func VerifyPhoneNumber(user *User) error {
	// Simulate SMS sending
	fmt.Printf("Verification SMS sent to %s\n", user.PhoneNumber)
	return nil
}

// DeleteUser deletes a user from the system
func DeleteUser(user *User) {
	// Simulate user deletion
	fmt.Printf("User %s deleted\n", user.Username)
}
