package security

import (
	"errors"
	"time"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
)

// AccessControl manages user access control and authentication.
type AccessControl struct {
	users           map[string]User
	eventDispatcher events.EventDispatcher
	mutex           sync.Mutex
}

type User struct {
	ID                string
	Username          string
	Email             string
	HashedPassword    string
	Role              string
	RegisteredAt      time.Time
	LastAuthenticated time.Time
}

// NewAccessControl creates a new AccessControl instance.
func NewAccessControl(eventDispatcher events.EventDispatcher) *AccessControl {
	return &AccessControl{
		users:           make(map[string]User),
		eventDispatcher: eventDispatcher,
	}
}

// RegisterUser registers a new user with the specified details.
func (ac *AccessControl) RegisterUser(username, email, password, role string) (string, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	userID := generateUserID(username, email)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	user := User{
		ID:             userID,
		Username:       username,
		Email:          email,
		HashedPassword: string(hashedPassword),
		Role:           role,
		RegisteredAt:   time.Now(),
	}

	ac.users[userID] = user

	event := events.Event{
		Type:    events.UserRegistered,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ac.eventDispatcher.Dispatch(event); err != nil {
		return "", err
	}

	return userID, nil
}

// AuthenticateUser authenticates a user by username and password.
func (ac *AccessControl) AuthenticateUser(username, password string) (string, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	for _, user := range ac.users {
		if user.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
				return "", errors.New("authentication failed")
			}
			user.LastAuthenticated = time.Now()
			ac.users[user.ID] = user
			return user.ID, nil
		}
	}

	return "", errors.New("user not found")
}

// ChangePassword changes the password for a specified user.
func (ac *AccessControl) ChangePassword(userID, oldPassword, newPassword string) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	user, exists := ac.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword)); err != nil {
		return errors.New("incorrect old password")
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.HashedPassword = string(newHashedPassword)
	ac.users[userID] = user

	event := events.Event{
		Type:    events.PasswordChanged,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ac.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

// GrantRole grants a new role to a specified user.
func (ac *AccessControl) GrantRole(userID, newRole string) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	user, exists := ac.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Role = newRole
	ac.users[userID] = user

	event := events.Event{
		Type:    events.RoleGranted,
		Payload: map[string]interface{}{"userID": userID, "newRole": newRole},
	}
	if err := ac.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

// RevokeRole revokes the role of a specified user.
func (ac *AccessControl) RevokeRole(userID string) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	user, exists := ac.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.Role = ""
	ac.users[userID] = user

	event := events.Event{
		Type:    events.RoleRevoked,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ac.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

// GetUser retrieves the details of a specified user.
func (ac *AccessControl) GetUser(userID string) (User, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	user, exists := ac.users[userID]
	if !exists {
		return User{}, errors.New("user not found")
	}

	return user, nil
}

// ListUsers lists all registered users.
func (ac *AccessControl) ListUsers() ([]User, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	var userList []User
	for _, user := range ac.users {
		userList = append(userList, user)
	}

	return userList, nil
}

// RemoveUser removes a user from the system.
func (ac *AccessControl) RemoveUser(userID string) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	if _, exists := ac.users[userID]; !exists {
		return errors.New("user not found")
	}

	delete(ac.users, userID)

	event := events.Event{
		Type:    events.UserRemoved,
		Payload: map[string]interface{}{"userID": userID},
	}
	if err := ac.eventDispatcher.Dispatch(event); err != nil {
		return err
	}

	return nil
}

func generateUserID(username, email string) string {
	// Implement a unique user ID generation logic
	return fmt.Sprintf("%x", sha256.Sum256([]byte(username+email+time.Now().String())))
}

