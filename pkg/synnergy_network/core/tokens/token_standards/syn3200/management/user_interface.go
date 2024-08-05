package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// User represents a user in the system.
type User struct {
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	CreatedDate time.Time `json:"created_date"`
}

// UserInterface represents the user interface for managing users.
type UserInterface struct {
	DB *leveldb.DB
}

// NewUserInterface creates a new UserInterface instance.
func NewUserInterface(dbPath string) (*UserInterface, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &UserInterface{DB: db}, nil
}

// CloseDB closes the database connection.
func (ui *UserInterface) CloseDB() error {
	return ui.DB.Close()
}

// AddUser adds a new user to the system.
func (ui *UserInterface) AddUser(user User) error {
	if err := ui.ValidateUser(user); err != nil {
		return err
	}
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ui.DB.Put([]byte("user_"+user.UserID), data, nil)
}

// GetUser retrieves a user by their user ID.
func (ui *UserInterface) GetUser(userID string) (*User, error) {
	data, err := ui.DB.Get([]byte("user_"+userID), nil)
	if err != nil {
		return nil, err
	}
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetAllUsers retrieves all users from the system.
func (ui *UserInterface) GetAllUsers() ([]User, error) {
	var users []User
	iter := ui.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var user User
		if err := json.Unmarshal(iter.Value(), &user); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return users, nil
}

// ValidateUser ensures the user is valid before adding them to the system.
func (ui *UserInterface) ValidateUser(user User) error {
	if user.UserID == "" {
		return errors.New("user ID must be provided")
	}
	if user.Name == "" {
		return errors.New("user name must be provided")
	}
	if user.Email == "" {
		return errors.New("user email must be provided")
	}
	if user.Role == "" {
		return errors.New("user role must be provided")
	}
	return nil
}

// UpdateUser updates an existing user in the system.
func (ui *UserInterface) UpdateUser(user User) error {
	if _, err := ui.GetUser(user.UserID); err != nil {
		return err
	}
	if err := ui.ValidateUser(user); err != nil {
		return err
	}
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ui.DB.Put([]byte("user_"+user.UserID), data, nil)
}

// DeleteUser removes a user from the system.
func (ui *UserInterface) DeleteUser(userID string) error {
	return ui.DB.Delete([]byte("user_"+userID), nil)
}

// RoleManagement provides role-based access control.
type RoleManagement struct {
	DB *leveldb.DB
}

// NewRoleManagement creates a new RoleManagement instance.
func NewRoleManagement(dbPath string) (*RoleManagement, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &RoleManagement{DB: db}, nil
}

// AddRole adds a new role to the system.
func (rm *RoleManagement) AddRole(role string) error {
	if role == "" {
		return errors.New("role must be provided")
	}
	return rm.DB.Put([]byte("role_"+role), []byte(role), nil)
}

// GetRole retrieves a role from the system.
func (rm *RoleManagement) GetRole(role string) (string, error) {
	data, err := rm.DB.Get([]byte("role_"+role), nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetAllRoles retrieves all roles from the system.
func (rm *RoleManagement) GetAllRoles() ([]string, error) {
	var roles []string
	iter := rm.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		roles = append(roles, string(iter.Value()))
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return roles, nil
}

// DeleteRole removes a role from the system.
func (rm *RoleManagement) DeleteRole(role string) error {
	return rm.DB.Delete([]byte("role_"+role), nil)
}

// AssignRole assigns a role to a user.
func (rm *RoleManagement) AssignRole(userID, role string) error {
	userInterface := &UserInterface{DB: rm.DB}
	user, err := userInterface.GetUser(userID)
	if err != nil {
		return err
	}
	if _, err := rm.GetRole(role); err != nil {
		return err
	}
	user.Role = role
	return userInterface.UpdateUser(*user)
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
}

// AuditLogManagement manages audit logs.
type AuditLogManagement struct {
	DB *leveldb.DB
}

// NewAuditLogManagement creates a new AuditLogManagement instance.
func NewAuditLogManagement(dbPath string) (*AuditLogManagement, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &AuditLogManagement{DB: db}, nil
}

// AddAuditLog adds a new audit log entry to the system.
func (alm *AuditLogManagement) AddAuditLog(log AuditLog) error {
	data, err := json.Marshal(log)
	if err != nil {
		return err
	}
	return alm.DB.Put([]byte("auditlog_"+fmt.Sprint(log.Timestamp.UnixNano())), data, nil)
}

// GetAuditLogs retrieves all audit logs from the system.
func (alm *AuditLogManagement) GetAuditLogs() ([]AuditLog, error) {
	var logs []AuditLog
	iter := alm.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var log AuditLog
		if err := json.Unmarshal(iter.Value(), &log); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return logs, nil
}
