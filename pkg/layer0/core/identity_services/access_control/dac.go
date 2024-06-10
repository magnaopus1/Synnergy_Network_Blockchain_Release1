package identity_services

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "log"
    "net/http"

    "golang.org/x/crypto/argon2"
)

// AccessControlList defines the structure for discretionary access control lists.
type AccessControlList struct {
    ResourceID string
    Permissions map[string][]string // Maps user IDs to allowed actions
}

// DACSystem represents the discretionary access control system.
type DACSystem struct {
    ACLs map[string]*AccessControlList
}

// NewDACSystem initializes a new discretionary access control system.
func NewDACSystem() *DACSystem {
    return &DACSystem{
        ACLs: make(map[string]*AccessControlList),
    }
}

// SetPermissions sets the permissions for a user on a specific resource.
func (dac *DACSystem) SetPermissions(resourceID, userID string, actions []string) {
    if acl, exists := dac.ACLs[resourceID]; exists {
        acl.Permissions[userID] = actions
    } else {
        dac.ACLs[resourceID] = &AccessControlList{
            ResourceID: resourceID,
            Permissions: map[string][]string{userID: actions},
        }
    }
    log.Printf("Permissions set for user %s on resource %s: %v", userID, resourceID, actions)
}

// CheckAccess checks if a user has permission to perform an action on a resource.
func (dac *DACSystem) CheckAccess(userID, resourceID, action string) bool {
    if acl, exists := dac.ACLs[resourceID]; exists {
        if actions, ok := acl.Permissions[userID]; ok {
            for _, act := range actions {
                if act == action {
                    return true
                }
            }
        }
    }
    return false
}

// AccessHandler handles HTTP requests for access checks.
func (dac *DACSystem) AccessHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    resourceID := r.URL.Query().Get("resource_id")
    action := r.URL.Query().Get("action")

    if dac.CheckAccess(userID, resourceID, action) {
        fmt.Fprintf(w, "Access granted for %s on %s to perform %s", userID, resourceID, action)
    } else {
        http.Error(w, "Access denied", http.StatusForbidden)
    }
}

func main() {
    dac := NewDACSystem()
    http.HandleFunc("/check_access", dac.AccessHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
