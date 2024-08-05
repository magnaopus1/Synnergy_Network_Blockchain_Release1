package management

import (
	"fmt"
	"sync"
	"time"
)

type User struct {
	ID        string
	Name      string
	PublicKey string
	CreatedAt time.Time
}

type UserManager struct {
	users map[string]User
	mutex sync.Mutex
}

func NewUserManager() *UserManager {
	return &UserManager{
		users: make(map[string]User),
	}
}

// AddUser adds a new user to the system
func (um *UserManager) AddUser(id, name, publicKey string) error {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	if _, exists := um.users[id]; exists {
		return fmt.Errorf("user with ID %s already exists", id)
	}

	user := User{
		ID:        id,
		Name:      name,
		PublicKey: publicKey,
		CreatedAt: time.Now(),
	}

	um.users[id] = user
	return nil
}

// UpdateUser updates the details of an existing user
func (um *UserManager) UpdateUser(id, name, publicKey string) error {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	user, exists := um.users[id]
	if !exists {
		return fmt.Errorf("user with ID %s not found", id)
	}

	user.Name = name
	user.PublicKey = publicKey
	um.users[id] = user

	return nil
}

// GetUser retrieves a user's details by their ID
func (um *UserManager) GetUser(id string) (User, error) {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	user, exists := um.users[id]
	if !exists {
		return User{}, fmt.Errorf("user with ID %s not found", id)
	}

	return user, nil
}

// DeleteUser removes a user from the system
func (um *UserManager) DeleteUser(id string) error {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	if _, exists := um.users[id]; !exists {
		return fmt.Errorf("user with ID %s not found", id)
	}

	delete(um.users, id)
	return nil
}

// ListUsers retrieves all users in the system
func (um *UserManager) ListUsers() []User {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	var userList []User
	for _, user := range um.users {
		userList = append(userList, user)
	}

	return userList
}

// GrantRole grants a specific role to a user
func (um *UserManager) GrantRole(userID, role string) error {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	user, exists := um.users[userID]
	if !exists {
		return fmt.Errorf("user with ID %s not found", userID)
	}

	// Placeholder logic for granting role
	// user.Roles = append(user.Roles, role)
	um.users[userID] = user

	return nil
}

// RevokeRole revokes a specific role from a user
func (um *UserManager) RevokeRole(userID, role string) error {
	um.mutex.Lock()
	defer um.mutex.Unlock()

	user, exists := um.users[userID]
	if !exists {
		return fmt.Errorf("user with ID %s not found", userID)
	}

	// Placeholder logic for revoking role
	// user.Roles = remove(user.Roles, role)
	um.users[userID] = user

	return nil
}

// Placeholder function to illustrate role removal
// func remove(slice []string, item string) []string {
// 	for i, other := range slice {
// 		if other == item {
// 			return append(slice[:i], slice[i+1:]...)
// 		}
// 	}
// 	return slice
// }
