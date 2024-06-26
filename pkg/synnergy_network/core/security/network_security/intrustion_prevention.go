package security

import (
    "log"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "net"
    "net/http"
    "strings"
)

const (
    Salt = "secure-random-salt"
    KeyLength = 32
)

// IntrusionPreventionSystem holds settings for the IPS
type IntrusionPreventionSystem struct {
    BlockedIPs map[string]bool
}

// NewIntrusionPreventionSystem initializes the Intrusion Prevention System with default settings
func NewIntrusionPreventionSystem() *IntrusionPreventionSystem {
    return &IntrusionPreventionSystem{
        BlockedIPs: make(map[string]bool),
    }
}

// BlockIP blocks an IP address
func (ips *IntrusionPreventionSystem) BlockIP(ip string) {
    ips.BlockedIPs[ip] = true
    log.Printf("Blocked IP: %s", ip)
}

// UnblockIP unblocks an IP address
func (ips *IntrusionPreventionSystem) UnblockIP(ip string) {
    delete(ips.BlockedIPs, ip)
    log.Printf("Unblocked IP: %s", ip)
}

// CheckIP checks if an IP is blocked
func (ips *IntrusionPreventionSystem) CheckIP(ip string) bool {
    return ips.BlockedIPs[ip]
}

// Middleware to intercept and check requests for blocked IPs
func (ips *IntrusionPreventionSystem) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := strings.Split(r.RemoteAddr, ":")[0]
        if ips.CheckIP(ip) {
            http.Error(w, "Access Denied", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// EncryptData uses Argon2 to encrypt data
func EncryptData(data []byte) []byte {
    salt := []byte(Salt)
    key := argon2.IDKey(data, salt, 1, 64*1024, 4, KeyLength)
    return key
}

// DecryptData uses Scrypt to decrypt data
func DecryptData(data []byte) ([]byte, error) {
    dk, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
    if err != nil {
        log.Fatal(err)
        return nil, err
    }
    return dk, nil
}

// main function to demonstrate the use of IPS
func main() {
    ips := NewIntrusionPreventionSystem()
    ips.BlockIP("192.168.1.1")

    // Example HTTP server using IPS middleware
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Welcome, your IP is not blocked!"))
    })

    wrappedMux := ips.Middleware(mux)
    http.ListenAndServe(":8080", wrappedMux)
}
