package security

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/time/rate"
)

const (
	Salt       = "your-secure-unique-salt"
	KeyLength  = 32
	ArgonTime  = 1
	ArgonMemory = 64 * 1024
	ArgonThreads = 4
	ArgonKeyLength = 32
	MaxRequestsPerSecond = 5
	BurstLimit = 10
)

// RateLimiter struct to limit requests from a single IP
type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.Mutex
}

// NewRateLimiter creates a new RateLimiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
	}
}

// GetLimiter returns a rate limiter for a given IP, creates new one if not exists
func (l *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limiter, exists := l.visitors[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Limit(MaxRequestsPerSecond), BurstLimit)
	l.visitors[ip] = limiter
	return limiter
}

// Middleware to handle DDoS protection
func (l *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := l.GetLimiter(r.RemoteAddr)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// EncryptData uses Argon2 for data encryption
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
	rateLimiter := NewRateLimiter()
	http.Handle("/", rateLimiter.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the request
		w.Write([]byte("Hello, world!"))
	})))

	// Start the HTTP server with rate limiting
	http.ListenAndServe(":8080", nil)
}
