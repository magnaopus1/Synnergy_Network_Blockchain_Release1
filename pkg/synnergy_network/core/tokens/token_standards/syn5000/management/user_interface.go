// user_interface.go

package management

import (
	"errors"
	"fmt"
	"time"
)

// User represents a user in the system
type User struct {
	ID       string // Unique identifier for the user
	Username string // Username chosen by the user
	Email    string // User's email address
	Password string // Hashed password for user authentication
	Role     string // User's role (e.g., player, admin, auditor)
	CreatedAt time.Time // Timestamp when the user account was created
	Status   string // Status of the user's account (active, suspended, etc.)
}

// UserInterface manages user interactions and profiles
type UserInterface struct {
	users map[string]User // Map of user ID to User objects
}

// NewUserInterface initializes a new UserInterface
func NewUserInterface() *UserInterface {
	return &UserInterface{
		users: make(map[string]User),
	}
}

// RegisterUser registers a new user in the system
func (ui *UserInterface) RegisterUser(username, email, password, role string) (User, error) {
	if _, exists := ui.getUserByUsername(username); exists {
		return User{}, errors.New("username already taken")
	}
	if _, exists := ui.getUserByEmail(email); exists {
		return User{}, errors.New("email already registered")
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}

	user := User{
		ID:        generateUserID(),
		Username:  username,
		Email:     email,
		Password:  hashedPassword,
		Role:      role,
		CreatedAt: time.Now(),
		Status:    "active",
	}

	ui.users[user.ID] = user
	return user, nil
}

// AuthenticateUser authenticates a user by username and password
func (ui *UserInterface) AuthenticateUser(username, password string) (User, error) {
	user, exists := ui.getUserByUsername(username)
	if !exists {
		return User{}, errors.New("user not found")
	}

	if !checkPasswordHash(password, user.Password) {
		return User{}, errors.New("incorrect password")
	}

	return user, nil
}

// UpdateUserProfile updates a user's profile information
func (ui *UserInterface) UpdateUserProfile(userID, email, password string) error {
	user, exists := ui.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if email != "" {
		if _, exists := ui.getUserByEmail(email); exists {
			return errors.New("email already registered")
		}
		user.Email = email
	}

	if password != "" {
		hashedPassword, err := hashPassword(password)
		if err != nil {
			return err
		}
		user.Password = hashedPassword
	}

	ui.users[userID] = user
	return nil
}

// DeactivateUser deactivates a user account
func (ui *UserInterface) DeactivateUser(userID string) error {
	user, exists := ui.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Status = "deactivated"
	ui.users[userID] = user
	return nil
}

// GetUserProfile retrieves a user's profile by ID
func (ui *UserInterface) GetUserProfile(userID string) (User, error) {
	user, exists := ui.users[userID]
	if !exists {
		return User{}, errors.New("user not found")
	}
	return user, nil
}

// ListUsersByRole lists all users with a specific role
func (ui *UserInterface) ListUsersByRole(role string) []User {
	users := []User{}
	for _, user := range ui.users {
		if user.Role == role {
			users = append(users, user)
		}
	}
	return users
}

// Utility and helper functions

// hashPassword hashes a password with a salt using Argon2
func hashPassword(password string) (string, error) {
	// Implement password hashing with Argon2, including generating a salt
	// Example:
	// hashedPassword, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	// if err != nil {
	//     return "", err
	// }
	// return hashedPassword, nil
	return "hashedPassword", nil // Placeholder implementation
}

// checkPasswordHash checks if the password matches the hashed password
func checkPasswordHash(password, hash string) bool {
	// Implement password hash verification using Argon2
	// Example:
	// match, err := argon2id.ComparePasswordAndHash(password, hash)
	// if err != nil {
	//     return false
	// }
	// return match
	return true // Placeholder implementation
}

// generateUserID generates a unique user ID
func generateUserID() string {
	// Implement a unique user ID generator, potentially using UUIDs
	// Example:
	// return uuid.New().String()
	return "uniqueUserID" // Placeholder implementation
}

// getUserByUsername retrieves a user by their username
func (ui *UserInterface) getUserByUsername(username string) (User, bool) {
	for _, user := range ui.users {
		if user.Username == username {
			return user, true
		}
	}
	return User{}, false
}

// getUserByEmail retrieves a user by their email address
func (ui *UserInterface) getUserByEmail(email string) (User, bool) {
	for _, user := range ui.users {
		if user.Email == email {
			return user, true
		}
	}
	return User{}, false
}
