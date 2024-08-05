package identity

import (
	"errors"
	"time"
)

type UserIdentity struct {
	ID        string
	Name      string
	Email     string
	CreatedAt time.Time
}

type IdentityManager struct {
	Users map[string]*UserIdentity
}

func NewIdentityManager() *IdentityManager {
	return &IdentityManager{
		Users: make(map[string]*UserIdentity),
	}
}

func (im *IdentityManager) AddUser(id, name, email string) {
	im.Users[id] = &UserIdentity{
		ID:        id,
		Name:      name,
		Email:     email,
		CreatedAt: time.Now(),
	}
}

func (im *IdentityManager) GetUser(id string) (*UserIdentity, error) {
	user, exists := im.Users[id]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (im *IdentityManager) RemoveUser(id string) {
	delete(im.Users, id)
}

func (im *IdentityManager) ListUsers() []*UserIdentity {
	var users []*UserIdentity
	for _, user := range im.Users {
		users = append(users, user)
	}
	return users
}
