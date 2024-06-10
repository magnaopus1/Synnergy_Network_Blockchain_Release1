package security

import (
    "log"
    "net/http"
    "strings"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt = "unique-salt-string"
    KeyLength = 32
)

// IntrusionBlocker manages the blocking of identified threats
type IntrusionBlocker struct {
    BlockedIPs map[string]bool
}

// NewIntrusionBlocker initializes a new IntrusionBlocker
func NewIntrusionBlocker() *IntrusionBlocker {
    return &IntrusionBlocker{
        BlockedIPs: make(map[string]bool),
    }
}

// BlockIP adds an IP address to the block list
func (ib *IntrusionBlocker) BlockIP(ip string) {
    ib.BlockedIPs[ip] = true
    log.Printf("Blocked IP: %s", ip)
}

// UnblockIP removes an IP address from the block list
func (ib *IntrusionBlocker) UnblockIP(ip string) {
    delete(ib.BlockedIPs, ip)
    log.Printf("Unblocked IP: %s", ip)
}

// IsBlocked checks if an IP is on the block list
func (ib *IntrusionBlocker) IsBlocked(ip string) bool {
    return ib.BlockedIPs[ip]
}

// Middleware to intercept and block requests from blacklisted IPs
func (ib *IntrusionBlocker) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := strings.Split(r.RemoteAddr, ":")[0]
        if ib.IsBlocked(ip) {
            http.Error(w, "Access Denied", http.StatusForbidden)
            log.Printf("Blocked access attempt from IP: %s", ip)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// EncryptData provides a utility to encrypt data using Argon2
func EncryptData(data []byte) []byte {
    salt := []byte(Salt)
    return argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
}

// DecryptData provides a utility to decrypt data using Scrypt
func DecryptData(encryptedData []byte) ([]byte, error) {
    dk, err := scrypt.Key(encryptedData, []byte(Salt), 16384, 8, 1, KeyLength)
    if err != nil {
        log.Printf("Error decrypting data: %v", err)
        return nil, err
    }
    return dk, nil
}

// Example setup and usage of the IntrusionBlocker
func main() {
    blocker := NewIntrusionBlocker()
    blocker.BlockIP("192.168.1.1")

    mux := http.NewServeMux()
    mux.Handle("/", blocker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, world!"))
    })))

    log.Println("Starting server on port 8080...")
    if err := http.ListenAndServe(":8080", mux); err != nil {
        log.Fatal("Failed to start server: ", err)
    }
}
