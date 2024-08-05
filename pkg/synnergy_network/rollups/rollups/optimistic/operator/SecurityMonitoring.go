package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// SecurityEvent represents a security-related event in the blockchain network.
type SecurityEvent struct {
	Timestamp time.Time
	Event     string
	NodeID    string
	Severity  string
}

// SecurityMonitoring handles security monitoring and incident response in the blockchain network.
type SecurityMonitoring struct {
	mu             sync.Mutex
	events         []SecurityEvent
	nodeHealth     map[string]string
	alertThreshold int
	alertHandlers  []func(SecurityEvent)
}

// NewSecurityMonitoring initializes a new instance of SecurityMonitoring.
func NewSecurityMonitoring(alertThreshold int) *SecurityMonitoring {
	return &SecurityMonitoring{
		nodeHealth:     make(map[string]string),
		alertThreshold: alertThreshold,
	}
}

// LogEvent logs a security event.
func (sm *SecurityMonitoring) LogEvent(event string, nodeID string, severity string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	newEvent := SecurityEvent{
		Timestamp: time.Now(),
		Event:     event,
		NodeID:    nodeID,
		Severity:  severity,
	}

	sm.events = append(sm.events, newEvent)
	fmt.Printf("Security Event Logged: %+v\n", newEvent)

	if severity == "HIGH" {
		sm.triggerAlerts(newEvent)
	}
}

// UpdateNodeHealth updates the health status of a node.
func (sm *SecurityMonitoring) UpdateNodeHealth(nodeID string, healthStatus string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.nodeHealth[nodeID] = healthStatus
	fmt.Printf("Node %s Health Updated to %s\n", nodeID, healthStatus)
}

// triggerAlerts triggers alerts for critical security events.
func (sm *SecurityMonitoring) triggerAlerts(event SecurityEvent) {
	for _, handler := range sm.alertHandlers {
		handler(event)
	}
}

// AddAlertHandler adds an alert handler for critical security events.
func (sm *SecurityMonitoring) AddAlertHandler(handler func(SecurityEvent)) {
	sm.alertHandlers = append(sm.alertHandlers, handler)
}

// GenerateSecurityToken generates a secure token using scrypt.
func GenerateSecurityToken(password string, salt []byte) (string, error) {
	dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dk), nil
}

// VerifySecurityToken verifies a security token using scrypt.
func VerifySecurityToken(password, token string, salt []byte) bool {
	dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return false
	}
	return hex.EncodeToString(dk) == token
}

// EncryptData encrypts data using SHA-256.
func EncryptData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// PrintSecuritySummary prints a summary of security events and node health.
func (sm *SecurityMonitoring) PrintSecuritySummary() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	fmt.Println("Security Monitoring Summary")
	fmt.Printf("Total Security Events: %d\n", len(sm.events))
	fmt.Println("Node Health Status:")
	for node, status := range sm.nodeHealth {
		fmt.Printf("Node %s: %s\n", node, status)
	}
}

// ExportSecurityMetrics exports security metrics for monitoring tools.
func (sm *SecurityMonitoring) ExportSecurityMetrics() map[string]interface{} {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	metrics := map[string]interface{}{
		"totalEvents": len(sm.events),
		"nodeHealth":  sm.nodeHealth,
	}

	return metrics
}
