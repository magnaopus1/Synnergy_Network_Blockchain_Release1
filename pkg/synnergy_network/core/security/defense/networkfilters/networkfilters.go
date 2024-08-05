package networkfilters

import (
    "net"
    "sync"
    "time"
    "log"
)

// NetworkFilterService manages network filters for incoming and outgoing traffic
type NetworkFilterService struct {
    ipWhitelist     map[string]bool
    ipBlacklist     map[string]time.Time
    blacklistExpiry time.Duration
    mu              sync.Mutex
}

// NewNetworkFilterService initializes a new network filter service
func NewNetworkFilterService(blacklistExpiry time.Duration) *NetworkFilterService {
    return &NetworkFilterService{
        ipWhitelist:     make(map[string]bool),
        ipBlacklist:     make(map[string]time.Time),
        blacklistExpiry: blacklistExpiry,
    }
}

// AllowIP adds an IP address to the whitelist
func (nfs *NetworkFilterService) AllowIP(ip string) {
    nfs.mu.Lock()
    defer nfs.mu.Unlock()
    nfs.ipWhitelist[ip] = true
    log.Printf("Allowed IP: %s", ip)
}

// BlockIP adds an IP address to the blacklist
func (nfs *NetworkFilterService) BlockIP(ip string) {
    nfs.mu.Lock()
    defer nfs.mu.Unlock()
    nfs.ipBlacklist[ip] = time.Now()
    log.Printf("Blocked IP: %s", ip)
}

// RemoveIP removes an IP address from the whitelist and blacklist
func (nfs *NetworkFilterService) RemoveIP(ip string) {
    nfs.mu.Lock()
    defer nfs.mu.Unlock()
    delete(nfs.ipWhitelist, ip)
    delete(nfs.ipBlacklist, ip)
    log.Printf("Removed IP: %s", ip)
}

// IsAllowed checks if an IP address is allowed
func (nfs *NetworkFilterService) IsAllowed(ip string) bool {
    nfs.mu.Lock()
    defer nfs.mu.Unlock()
    if _, whitelisted := nfs.ipWhitelist[ip]; whitelisted {
        return true
    }
    if blacklistTime, blacklisted := nfs.ipBlacklist[ip]; blacklisted {
        if time.Since(blacklistTime) > nfs.blacklistExpiry {
            delete(nfs.ipBlacklist, ip)
            log.Printf("Expired and removed blacklisted IP: %s", ip)
            return true
        }
        return false
    }
    return true
}

// ClearExpiredBlocks clears expired IP addresses from the blacklist
func (nfs *NetworkFilterService) ClearExpiredBlocks() {
    nfs.mu.Lock()
    defer nfs.mu.Unlock()
    for ip, blacklistTime := range nfs.ipBlacklist {
        if time.Since(blacklistTime) > nfs.blacklistExpiry {
            delete(nfs.ipBlacklist, ip)
            log.Printf("Cleared expired blacklisted IP: %s", ip)
        }
    }
}

// FilterTraffic applies filters to a given IP address
func (nfs *NetworkFilterService) FilterTraffic(ip string) bool {
    if net.ParseIP(ip) == nil {
        log.Printf("Invalid IP address: %s", ip)
        return false
    }
    if !nfs.IsAllowed(ip) {
        log.Printf("Blocked traffic from IP: %s", ip)
        return false
    }
    log.Printf("Allowed traffic from IP: %s", ip)
    return true
}

// StartPeriodicCleanup starts a routine to periodically clear expired blacklisted IPs
func (nfs *NetworkFilterService) StartPeriodicCleanup(interval time.Duration) {
    go func() {
        for {
            time.Sleep(interval)
            nfs.ClearExpiredBlocks()
        }
    }()
}
