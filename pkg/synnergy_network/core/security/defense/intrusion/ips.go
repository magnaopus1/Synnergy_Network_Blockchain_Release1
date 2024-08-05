package intrusion

import (
    "log"
    "sync"
    "time"

    "github.com/yourorg/yourproject/network"
    "github.com/yourorg/yourproject/models"
    "github.com/yourorg/yourproject/cryptography"
)

// IntrusionPreventionService defines the structure for the IPS
type IntrusionPreventionService struct {
    blockList       map[string]time.Time
    alertThreshold  int
    blockDuration   time.Duration
    mu              sync.Mutex
    ids             *IntrusionDetectionService
}

// NewIntrusionPreventionService initializes a new IPS with a reference to an IDS
func NewIntrusionPreventionService(ids *IntrusionDetectionService, blockDuration time.Duration) *IntrusionPreventionService {
    return &IntrusionPreventionService{
        blockList:      make(map[string]time.Time),
        alertThreshold: 10, // Number of alerts before blocking
        blockDuration:  blockDuration,
        ids:            ids,
    }
}

// MonitorAndPrevent monitors network traffic and applies prevention mechanisms
func (ips *IntrusionPreventionService) MonitorAndPrevent(packet *network.Packet) {
    ips.mu.Lock()
    defer ips.mu.Unlock()

    // Check if the source IP is in the blocklist
    if blockTime, blocked := ips.blockList[packet.SourceIP]; blocked {
        if time.Since(blockTime) < ips.blockDuration {
            log.Printf("Blocked packet from %s, still under block duration", packet.SourceIP)
            return
        }
        // Unblock if block duration has passed
        delete(ips.blockList, packet.SourceIP)
    }

    // Check for intrusions using IDS
    ips.ids.MonitorNetwork(packet)
    ips.handleAlerts()
}

// handleAlerts processes alerts from the IDS and takes appropriate action
func (ips *IntrusionPreventionService) handleAlerts() {
    for {
        select {
        case alert := <-ips.ids.alertQueue:
            ips.processAlert(alert)
        default:
            return
        }
    }
}

// processAlert processes individual alerts and decides on prevention actions
func (ips *IntrusionPreventionService) processAlert(alert *models.Alert) {
    log.Printf("Processing alert: %s", alert.Description)
    // For simplicity, we assume alert.ID contains the IP address
    if count, exists := ips.blockList[alert.ID]; exists {
        ips.blockList[alert.ID] = count + 1
    } else {
        ips.blockList[alert.ID] = 1
    }

    if ips.blockList[alert.ID] >= ips.alertThreshold {
        ips.blockIP(alert.ID)
    }
}

// blockIP blocks traffic from a specific IP address
func (ips *IntrusionPreventionService) blockIP(ip string) {
    log.Printf("Blocking IP: %s due to multiple alerts", ip)
    ips.blockList[ip] = time.Now()
}

// ClearOldBlocks clears expired blocks to keep the block list efficient
func (ips *IntrusionPreventionService) ClearOldBlocks() {
    ips.mu.Lock()
    defer ips.mu.Unlock()

    now := time.Now()
    for ip, blockTime := range ips.blockList {
        if now.Sub(blockTime) > ips.blockDuration {
            delete(ips.blockList, ip)
            log.Printf("Cleared block for IP: %s", ip)
        }
    }
}

// EncryptAlert encrypts alert information before logging or transmission
func (ips *IntrusionPreventionService) EncryptAlert(alert *models.Alert) (string, error) {
    encrypted, err := cryptography.Encrypt([]byte(alert.String()), "encryption-key")
    if err != nil {
        return "", err
    }
    return string(encrypted), nil
}
