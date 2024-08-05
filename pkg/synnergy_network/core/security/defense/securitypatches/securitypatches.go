package response

import (
    "fmt"
    "sync"
    "time"
    "crypto/rand"
    "encoding/hex"
    "github.com/synnergy_network/core/security/encryption"
    "github.com/synnergy_network/core/security/threatanalysis"
    "github.com/synnergy_network/core/security/identification"
    "github.com/synnergy_network/core/security/logging"
)

type Incident struct {
    ID            string
    Timestamp     time.Time
    Severity      string
    Description   string
    Resolved      bool
    ResponseSteps []string
}

type ResponseManager struct {
    incidents      map[string]*Incident
    lock           sync.RWMutex
    encryptionTool encryption.EncryptionTool
    threatAnalyzer threatanalysis.ThreatAnalyzer
    identifier     identification.Identifier
    logger         logging.Logger
}

func NewResponseManager() *ResponseManager {
    return &ResponseManager{
        incidents:      make(map[string]*Incident),
        encryptionTool: encryption.NewAESTool(),
        threatAnalyzer: threatanalysis.NewThreatAnalyzer(),
        identifier:     identification.NewIdentifier(),
        logger:         logging.NewLogger(),
    }
}

func (rm *ResponseManager) GenerateIncidentID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate incident ID: %v", err)
    }
    return hex.EncodeToString(bytes), nil
}

func (rm *ResponseManager) LogIncident(severity, description string) (*Incident, error) {
    rm.lock.Lock()
    defer rm.lock.Unlock()

    id, err := rm.GenerateIncidentID()
    if err != nil {
        return nil, err
    }

    incident := &Incident{
        ID:          id,
        Timestamp:   time.Now(),
        Severity:    severity,
        Description: description,
        Resolved:    false,
    }

    rm.incidents[id] = incident
    rm.logger.Log(fmt.Sprintf("New incident logged: %v", incident))

    return incident, nil
}

func (rm *ResponseManager) ResolveIncident(id string, responseSteps []string) error {
    rm.lock.Lock()
    defer rm.lock.Unlock()

    incident, exists := rm.incidents[id]
    if !exists {
        return fmt.Errorf("incident not found: %v", id)
    }

    incident.Resolved = true
    incident.ResponseSteps = responseSteps
    rm.logger.Log(fmt.Sprintf("Incident resolved: %v", incident))

    return nil
}

func (rm *ResponseManager) AnalyzeIncident(id string) (*threatanalysis.ThreatReport, error) {
    rm.lock.RLock()
    defer rm.lock.RUnlock()

    incident, exists := rm.incidents[id]
    if !exists {
        return nil, fmt.Errorf("incident not found: %v", id)
    }

    report, err := rm.threatAnalyzer.Analyze(incident.Description)
    if err != nil {
        return nil, fmt.Errorf("failed to analyze incident: %v", err)
    }

    rm.logger.Log(fmt.Sprintf("Incident analyzed: %v", report))

    return report, nil
}

func (rm *ResponseManager) IdentifySource(id string) (*identification.IdentityReport, error) {
    rm.lock.RLock()
    defer rm.lock.RUnlock()

    incident, exists := rm.incidents[id]
    if !exists {
        return nil, fmt.Errorf("incident not found: %v", id)
    }

    report, err := rm.identifier.Identify(incident.Description)
    if err != nil {
        return nil, fmt.Errorf("failed to identify source: %v", err)
    }

    rm.logger.Log(fmt.Sprintf("Source identified: %v", report))

    return report, nil
}

func (rm *ResponseManager) EncryptIncident(id string) (string, error) {
    rm.lock.RLock()
    defer rm.lock.RUnlock()

    incident, exists := rm.incidents[id]
    if !exists {
        return "", fmt.Errorf("incident not found: %v", id)
    }

    data, err := rm.encryptionTool.Encrypt([]byte(incident.Description))
    if err != nil {
        return "", fmt.Errorf("failed to encrypt incident: %v", err)
    }

    rm.logger.Log(fmt.Sprintf("Incident encrypted: %v", id))

    return hex.EncodeToString(data), nil
}

func (rm *ResponseManager) DecryptIncident(encryptedData string) (string, error) {
    rm.lock.RLock()
    defer rm.lock.RUnlock()

    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", fmt.Errorf("failed to decode encrypted data: %v", err)
    }

    decryptedData, err := rm.encryptionTool.Decrypt(data)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt incident: %v", err)
    }

    return string(decryptedData), nil
}

func (rm *ResponseManager) GetIncident(id string) (*Incident, error) {
    rm.lock.RLock()
    defer rm.lock.RUnlock()

    incident, exists := rm.incidents[id]
    if !exists {
        return nil, fmt.Errorf("incident not found: %v", id)
    }

    return incident, nil
}
