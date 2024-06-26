package ratelimiting

import (
	"time"

	"github.com/synthron/synthronchain/utils"
	"golang.org/x/time/rate"
)

// RateLimitConfig stores configuration for the network rate limiting.
type RateLimitConfig struct {
	GeneralLimit   rate.Limit
	BurstSize      int
	Whitelist      map[string]bool
	Blacklist      map[string]bool
	AdaptiveLimits map[string]AdaptiveRateLimit
}

// AdaptiveRateLimit provides configuration for dynamically adjusting rate limits.
type AdaptiveRateLimit struct {
	Limit     rate.Limit
	Burst     int
	Threshold int // Trigger threshold for adaptive adjustment
	Increase  rate.Limit // Rate increase factor
	Decrease  rate.Limit // Rate decrease factor
}

// NewRateLimitConfig creates a default rate limiting configuration.
func NewRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		GeneralLimit: rate.Limit(10), // 10 requests per second
		BurstSize:    20,
		Whitelist:    make(map[string]bool),
		Blacklist:    make(map[string]bool),
		AdaptiveLimits: map[string]AdaptiveRateLimit{
			"high_traffic": {
				Limit:     rate.Limit(20),
				Burst:     40,
				Threshold: 100,
				Increase:  rate.Limit(5),
				Decrease:  rate.Limit(15),
			},
		},
	}
}

// SetWhitelist updates the whitelist with a list of trusted IPs.
func (rlc *RateLimitConfig) SetWhitelist(ips []string) {
	for _, ip := range ips {
		rlc.Whitelist[ip] = true
	}
}

// SetBlacklist updates the blacklist with a list of blocked IPs.
func (rlc *RateLimitConfig) SetBlacklist(ips []string) {
	for _, ip := range ips {
		rlc.Blacklist[ip] = false
	}
}

// AdjustRateLimits dynamically adjusts rate limits based on network traffic analysis.
func (rlc *RateLimitConfig) AdjustRateLimits(currentLoad int) {
	for key, al := range rlc.AdaptiveLimits {
		if currentLoad > al.Threshold {
			rlc.AdaptiveLimits[key] = AdaptiveRateLimit{
				Limit:     al.Limit + al.Increase,
				Burst:     al.Burst,
				Threshold: al.Threshold,
				Increase:  al.Increase,
				Decrease:  al.Decrease,
			}
		} else {
			rlc.AdaptiveLimits[key] = AdaptiveRateLimit{
				Limit:     al.Limit - al.Decrease,
				Burst:     al.Burst,
				Threshold: al.Threshold,
				Increase:  al.Increase,
				Decrease:  al.Decrease,
			}
		}
	}
}

// Implement middleware and handlers to utilize these configurations in the network stack.
