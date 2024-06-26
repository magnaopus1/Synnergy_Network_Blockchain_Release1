package network_security

import (
    "errors"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/crypto/argon2"
    "sync"
)

const (
    Salt = "your-unique-salt-here"
    KeyLength = 32
)

// AccessControl represents the security mechanisms for access control in the network
type AccessControl struct {
    mutex sync.Mutex
    authorizedIPs map[string]bool
    accessKeys map[string][]byte
}

// NewAccessControl creates a new AccessControl instance
func NewAccessControl() *AccessControl {
    return &AccessControl{
        authorizedIPs: make(map[string]bool),
        accessKeys: make(map[string][]byte),
    }
}

// AuthorizeIP adds an IP address to the list of authorized IPs
func (ac *AccessControl) AuthorizeIP(ip string) {
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    ac.authorizedIPs[ip] = true
}

// RevokeIP removes an IP address from the list of authorized IPs
func (ac *AccessControl) RevokeIP(ip string) {
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    delete(ac.authorizedIPs, ip)
}

// AddAccessKey adds an access key for a user or service
func (ac *AccessControl) AddAccessKey(userID string, key []byte) error {
    saltedKey, err := argon2.IDKey(key, []byte(Salt), 1, 64*1024, 4, KeyLength)
    if err != nil {
        return err
    }
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    ac.accessKeys[userID] = saltedKey
    return nil
}

// ValidateAccess checks if the access key provided by a user or service is valid
func (ac *AccessControl) ValidateAccess(userID string, key []byte) bool {
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    if storedKey, exists := ac.accessKeys[userID]; exists {
        dk, _ := scrypt.Key(key, []byte(Salt), 16384, 8, 1, KeyLength)
        return string(dk) == string(storedKey)
    }
    return false
}

// IsIPAuthorized checks if the IP is authorized for network access
func (ac *AccessControl) IsIPAuthorized(ip string) bool {
    ac.mutex.Lock()
    defer ac.mutex.Unlock()
    _, authorized := ac.authorizedIPs[ip]
    return authorized
}
