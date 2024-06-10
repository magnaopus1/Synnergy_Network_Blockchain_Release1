package ratelimiting

import (
	"net/http"
	"sync"
	"golang.org/x/time/rate"
)

// RateLimiter controls the rate of incoming requests using token bucket algorithm.
type RateLimiter struct {
	limiters sync.Map // map for holding rate limiters per IP
	config   *RateLimitConfig
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config: config,
	}
}

// Middleware function to handle rate limiting for incoming HTTP requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // Simplified, in real scenarios, consider X-Forwarded-For
		if _, found := rl.config.Blacklist[ip]; found {
			http.Error(w, "Your IP is blacklisted.", http.StatusForbidden)
			return
		}

		limiter := rl.getRateLimiter(ip)
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getRateLimiter retrieves or creates a new rate limiter for a given IP.
func (rl *RateLimiter) getRateLimiter(ip string) *rate.Limiter {
	limiter, exists := rl.limiters.Load(ip)
	if !exists {
		newLimiter := rate.NewLimiter(rl.config.GeneralLimit, rl.config.BurstSize)
		rl.limiters.Store(ip, newLimiter)
		return newLimiter
	}
	return limiter.(*rate.Limiter)
}

// ApplyAdaptiveLimits adjusts limits based on current network traffic conditions.
func (rl *RateLimiter) ApplyAdaptiveLimits() {
	// Example: Adjust rate based on external metrics or internal conditions
	// This function should be called periodically or triggered by specific events
	for key, adaptive := range rl.config.AdaptiveLimits {
		// Adjust the general rate limit based on adaptive settings
		rl.config.GeneralLimit = adaptive.Limit // This is a simplification
	}
}

// RegisterRoutes for rate limiting configurations and management.
func (rl *RateLimiter) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("/admin/rate-limiter/config", func(w http.ResponseWriter, r *http.Request) {
		// Endpoint to configure rate-limiter settings dynamically
		if r.Method == "POST" {
			// Parse new settings from request and update rl.config
		}
	})
}
