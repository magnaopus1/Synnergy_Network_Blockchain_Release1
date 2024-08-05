package threatanalysis

import (
    "fmt"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "io"
    "sync"
)

// ThreatAnalyzer struct
type ThreatAnalyzer struct {
    mu               sync.Mutex
    detectedThreats  map[string]string
    forensicLogs     []string
    communityAlerts  chan string
    encryptionKey    []byte
}

// NewThreatAnalyzer creates a new instance of ThreatAnalyzer
func NewThreatAnalyzer(key []byte) *ThreatAnalyzer {
    return &ThreatAnalyzer{
        detectedThreats: make(map[string]string),
        forensicLogs:    []string{},
        communityAlerts: make(chan string, 100),
        encryptionKey:   key,
    }
}

// AnalyzeThreat uses AI to detect potential threats
func (ta *ThreatAnalyzer) AnalyzeThreat(data []byte) {
    // Implement AI-based threat analysis
    // Placeholder for actual machine learning integration
    if suspiciousActivityDetected(data) {
        ta.mu.Lock()
        defer ta.mu.Unlock()
        threatID := generateThreatID()
        ta.detectedThreats[threatID] = "Suspicious activity detected"
        ta.forensicLogs = append(ta.forensicLogs, fmt.Sprintf("Threat detected: %s", threatID))
        ta.communityAlerts <- fmt.Sprintf("Alert: Suspicious activity detected, ThreatID: %s", threatID)
    }
}

// suspiciousActivityDetected simulates threat detection logic
func suspiciousActivityDetected(data []byte) bool {
    // Placeholder logic for threat detection
    return len(data) > 100 // Example condition
}

// generateThreatID generates a unique identifier for threats
func generateThreatID() string {
    return fmt.Sprintf("threat-%d", rand.Int())
}

// EncryptData encrypts data using AES
func (ta *ThreatAnalyzer) EncryptData(plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(ta.encryptionKey)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

    return ciphertext, nil
}

// DecryptData decrypts data using AES
func (ta *ThreatAnalyzer) DecryptData(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(ta.encryptionKey)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return ciphertext, nil
}

// LogForensicData logs detailed information about detected threats
func (ta *ThreatAnalyzer) LogForensicData(threatID, details string) {
    ta.mu.Lock()
    defer ta.mu.Unlock()
    logEntry := fmt.Sprintf("ThreatID: %s, Details: %s", threatID, details)
    ta.forensicLogs = append(ta.forensicLogs, logEntry)
}

// GetCommunityAlerts retrieves the latest alerts for the community
func (ta *ThreatAnalyzer) GetCommunityAlerts() []string {
    ta.mu.Lock()
    defer ta.mu.Unlock()
    alerts := make([]string, 0, len(ta.communityAlerts))
    for {
        select {
        case alert := <-ta.communityAlerts:
            alerts = append(alerts, alert)
        default:
            return alerts
        }
    }
}

// SerializeLogs encrypts and serializes forensic logs
func (ta *ThreatAnalyzer) SerializeLogs() ([]byte, error) {
    ta.mu.Lock()
    defer ta.mu.Unlock()
    data, err := json.Marshal(ta.forensicLogs)
    if err != nil {
        return nil, err
    }
    return ta.EncryptData(data)
}
