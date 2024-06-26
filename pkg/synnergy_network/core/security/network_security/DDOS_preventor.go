package security

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/time/rate"
)

const (
	Salt          = "unique-salt-string"
	KeyLength     = 32
	ArgonTime     = 1
	ArgonMemory   = 64 * 1024
	ArgonThreads  = 4
	ArgonKeyLength = 32
	MaxRequestsPerMinute = 1000
	BurstCapacity = 20
)

var blacklist = sync.Map{}

// TrafficAnalyzer struct for analyzing request patterns
type TrafficAnalyzer struct {
	rateLimiters map[string]*rate.Limiter
	mu           sync.Mutex
}

// NewTrafficAnalyzer initializes a new Traffic Analyzer
func NewTrafficAnalyzer() *TrafficAnalyzer {
	return &TrafficAnalyzer{
		rateLimiters: make(map[string]*rate.Limiter),
	}
}

// GetLimiter retrieves or creates a new rate limiter for the IP
func (ta *TrafficAnalyzer) GetLimiter(ip string) *rate.Limiter {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	if limiter, exists := ta.rateLimiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Every(time.Minute/MaxRequestsPerMinute), BurstCapacity)
	ta.rateLimiters[ip] = limiter
	return limiter
}

// CheckBlacklist checks if an IP is blacklisted
func CheckBlacklist(ip string) bool {
	_, exists := blacklist.Load(ip)
	return exists
}

// AddToBlacklist adds an IP to the blacklist
func AddToBlacklist(ip string) {
	blacklist.Store(ip, true)
}

// Middleware for handling incoming requests
func (ta *TrafficAnalyzer) PreventDDoS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if CheckBlacklist(ip) {
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		limiter := ta.GetLimiter(ip)
		if !limiter.Allow() {
			AddToBlacklist(ip)
			http.Error(w, "Too Many Requests - You are being throttled", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// EncryptData uses Argon2 to encrypt data
func EncryptData(data []byte) []byte {
	salt := []byte(Salt)
	return argon2.IDKey(data, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLength)
}

// DecryptData uses Scrypt to decrypt data
func DecryptData(data []byte) ([]byte, error) {
	dk, err := scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
	if err != nil {
        return nil, err
    }
	return dk, nil
}

func main() {
	analyzer := NewTrafficAnalyzer()
	http.Handle("/", analyzer.PreventDDoS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Request successful"))
	})))

	http.ListenAndServe(":8080", nil)
}
