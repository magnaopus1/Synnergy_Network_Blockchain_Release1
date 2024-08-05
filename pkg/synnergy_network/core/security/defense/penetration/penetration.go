package penetration

import (
    "log"
    "sync"
    "time"
    "errors"
    "github.com/yourorg/yourproject/intrusion"
    "github.com/yourorg/yourproject/network"
)

// PenetrationPreventionService defines the structure for the penetration prevention system
type PenetrationPreventionService struct {
    alertThreshold    int
    blockDuration     time.Duration
    detectedIntrusions map[string]time.Time
    mu                sync.Mutex
    ids               *intrusion.IntrusionDetectionService
    alertQueue        chan intrusion.Alert
}

// NewPenetrationPreventionService initializes a new PenetrationPreventionService
func NewPenetrationPreventionService(ids *intrusion.IntrusionDetectionService, threshold int, duration time.Duration) *PenetrationPreventionService {
    return &PenetrationPreventionService{
        alertThreshold:    threshold,
        blockDuration:     duration,
        detectedIntrusions: make(map[string]time.Time),
        ids:               ids,
        alertQueue:        make(chan intrusion.Alert, 100),
    }
}

// MonitorTraffic monitors network traffic and applies prevention mechanisms
func (pps *PenetrationPreventionService) MonitorTraffic(packet *network.Packet) {
    pps.ids.MonitorNetwork(packet)
    pps.processAlerts()
}

// processAlerts processes alerts from the IDS and takes appropriate action
func (pps *PenetrationPreventionService) processAlerts() {
    for {
        select {
        case alert := <-pps.ids.AlertChannel():
            pps.handleAlert(alert)
        default:
            return
        }
    }
}

// handleAlert processes individual alerts and decides on prevention actions
func (pps *PenetrationPreventionService) handleAlert(alert intrusion.Alert) {
    pps.mu.Lock()
    defer pps.mu.Unlock()

    ip := alert.SourceIP
    if _, exists := pps.detectedIntrusions[ip]; exists {
        log.Printf("Repeated intrusion attempt detected from IP: %s", ip)
        pps.blockIP(ip)
    } else {
        log.Printf("Intrusion attempt detected from IP: %s", ip)
        pps.detectedIntrusions[ip] = time.Now()
    }
}

// blockIP blocks traffic from a specific IP address
func (pps *PenetrationPreventionService) blockIP(ip string) {
    log.Printf("Blocking IP: %s due to detected intrusion attempts", ip)
    pps.detectedIntrusions[ip] = time.Now().Add(pps.blockDuration)
}

// ClearExpiredBlocks clears expired IP addresses from the detected intrusions list
func (pps *PenetrationPreventionService) ClearExpiredBlocks() {
    pps.mu.Lock()
    defer pps.mu.Unlock()

    now := time.Now()
    for ip, blockedUntil := range pps.detectedIntrusions {
        if now.After(blockedUntil) {
            delete(pps.detectedIntrusions, ip)
            log.Printf("Cleared block for IP: %s", ip)
        }
    }
}

// AlertChannel returns the alert channel for external systems to listen for alerts
func (pps *PenetrationPreventionService) AlertChannel() <-chan intrusion.Alert {
    return pps.alertQueue
}

// RunPenetrationTests integrates with the penetration testing service for proactive testing
func (pps *PenetrationPreventionService) RunPenetrationTests() error {
    if pps.ids == nil {
        return errors.New("IDS service is not available")
    }

    // Placeholder for running automated penetration tests
    log.Println("Running penetration tests")
    // pps.ids.RunAllTests()

    return nil
}
