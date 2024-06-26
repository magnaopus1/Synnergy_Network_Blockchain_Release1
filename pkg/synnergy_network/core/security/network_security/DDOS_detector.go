package security

import (
	"log"
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
	Threshold     = 100 // Threshold for request count considered as potential DDoS
)

// RequestTracker keeps track of IP request counts
type RequestTracker struct {
	requestCounts map[string]int
	mu            sync.Mutex
}

// NewRequestTracker initializes a new Request Tracker
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		requestCounts: make(map[string]int),
	}
}

// IncrementRequestCount increases the count of requests from an IP
func (rt *RequestTracker) IncrementRequestCount(ip string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.requestCounts[ip]++
	if rt.requestCounts[ip] > Threshold {
		log.Printf("Potential DDoS attack detected from IP: %s", ip)
	}
}

// DDOSDetectionMiddleware to detect potential DDoS attacks based on frequency of requests
func DDOSDetectionMiddleware(next http.Handler) http.Handler {
	tracker := NewRequestTracker()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		tracker.IncrementRequestCount(ip)

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
	http.Handle("/", DDOSDetectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Request successful"))
	})))

	http.ListenAndServe(":8080", nil)
}
