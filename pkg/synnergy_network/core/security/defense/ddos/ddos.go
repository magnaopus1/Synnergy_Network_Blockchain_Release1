package ddos

import (
    "crypto/sha256"
    "encoding/hex"
    "log"
    "sync"
    "time"
)

// DDoSProtectionService handles the detection and mitigation of DDoS attacks
type DDoSProtectionService struct {
    requestLimit int
    timeWindow   time.Duration
    requestLog   map[string][]time.Time
    blacklist    map[string]bool
    mu           sync.Mutex
}

// NewDDoSProtectionService initializes a new DDoSProtectionService
func NewDDoSProtectionService(limit int, window time.Duration) *DDoSProtectionService {
    return &DDoSProtectionService{
        requestLimit: limit,
        timeWindow:   window,
        requestLog:   make(map[string][]time.Time),
        blacklist:    make(map[string]bool),
    }
}

// MonitorTraffic monitors and logs requests, identifies potential DDoS attempts
func (dps *DDoSProtectionService) MonitorTraffic(requestIP string) bool {
    dps.mu.Lock()
    defer dps.mu.Unlock()

    now := time.Now()
    if dps.blacklist[requestIP] {
        log.Printf("Blocked request from blacklisted IP: %s", requestIP)
        return false
    }

    logs, exists := dps.requestLog[requestIP]
    if !exists {
        logs = []time.Time{}
    }

    // Remove old logs
    threshold := now.Add(-dps.timeWindow)
    var newLogs []time.Time
    for _, logTime := range logs {
        if logTime.After(threshold) {
            newLogs = append(newLogs, logTime)
        }
    }
    dps.requestLog[requestIP] = newLogs

    // Check for DDoS
    if len(newLogs) >= dps.requestLimit {
        dps.blacklist[requestIP] = true
        log.Printf("IP %s blacklisted due to suspected DDoS", requestIP)
        return false
    }

    dps.requestLog[requestIP] = append(newLogs, now)
    return true
}

// HashIP uses SHA-256 to hash IP addresses for anonymization
func (dps *DDoSProtectionService) HashIP(ip string) string {
    hash := sha256.New()
    hash.Write([]byte(ip))
    return hex.EncodeToString(hash.Sum(nil))
}

// ClearBlacklist clears the blacklist after a certain time
func (dps *DDoSProtectionService) ClearBlacklist() {
    dps.mu.Lock()
    defer dps.mu.Unlock()

    // Placeholder for more complex logic, such as gradually removing entries or based on certain criteria
    for ip := range dps.blacklist {
        delete(dps.blacklist, ip)
    }
    log.Println("Cleared all blacklisted IPs")
}

// SetThreshold allows updating the request limit and time window for detection
func (dps *DDoSProtectionService) SetThreshold(limit int, window time.Duration) {
    dps.mu.Lock()
    defer dps.mu.Unlock()

    dps.requestLimit = limit
    dps.timeWindow = window
    log.Printf("Updated DDoS protection threshold: limit=%d, window=%v", limit, window)
}
