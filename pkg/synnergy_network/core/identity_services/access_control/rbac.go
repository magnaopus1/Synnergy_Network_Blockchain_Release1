package identity_services

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/json"
    "errors"
    "log"
    "net/http"
    "sync"

    "golang.org/x/crypto/argon2"
)

// Role defines a set of permissions associated with a group of users.
type Role struct {
    Name        string
    Permissions []string
}

// User defines the properties of a user in the system including their roles.
type User struct {
    ID    string
    Roles []string
}

// RBAC manages role-based access control.
type RBAC struct {
    roles map[string]Role
    users map[string]User
    sync.RWMutex
}

// NewRBAC creates a new instance of RBAC.
func NewRBAC() *RBAC {
    return &RBAC{
        roles: make(map[string]Role),
        users: make(map[string]User),
    }
}

// AddRole adds a new role to the RBAC system.
func (rbac *RBAC) AddRole(name string, permissions []string) error {
    rbac.Lock()
    defer rbac.Unlock()

    if _, exists := rbac.roles[name]; exists {
        return errors.New("role already exists")
    }

    rbac.roles[name] = Role{Name: name, Permissions: permissions}
    return nil
}

// AssignRole assigns a role to a user.
func (rbac *RBAC) AssignRole(userID, roleName string) error {
    rbac.Lock()
    defer rbac.Unlock()

    user, exists := rbac.users[userID]
    if !exists {
        return errors.New("user does not exist")
    }

    if _, exists := rbac.roles[roleName]; !exists {
        return errors.New("role does not exist")
    }

    // Add the role to user's roles if not already present
    for _, role := range user.Roles {
        if role == roleName {
            return nil // Role already assigned
        }
    }

    user.Roles = append(user.Roles, roleName)
    rbac.users[userID] = user
    return nil
}

// CheckPermission checks if a user has permission to perform an action.
func (rbac *RBAC) CheckPermission(userID, permission string) bool {
    rbac.RLock()
    defer rbac.RUnlock()

    user, exists := rbac.users[userID]
    if !exists {
        return false
    }

    for _, roleName := range user.Roles {
        role, exists := rbac.roles[roleName]
        if !exists {
            continue
        }

        for _, perm := range role.Permissions {
            if perm == permission {
                return true
            }
        }
    }

    return false
}

func main() {
    rbacSystem := NewRBAC()
    rbacSystem.AddRole("admin", []string{"create", "update", "delete"})
    rbacSystem.AddRole("user", []string{"read"})

    rbacSystem.AssignRole("user123", "admin")

    hasPermission := rbacSystem.CheckPermission("user123", "delete")
    log.Printf("Permission to delete: %v\n", hasPermission)
}
