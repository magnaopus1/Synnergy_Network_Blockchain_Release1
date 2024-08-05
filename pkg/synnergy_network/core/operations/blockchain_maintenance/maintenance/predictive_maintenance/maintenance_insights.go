package predictive_maintenance

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "sync"
    "time"
)

// MaintenanceInsight represents a structure to hold predictive maintenance insights
type MaintenanceInsight struct {
    ID             string
    Description    string
    Timestamp      time.Time
    ModelName      string
    Prediction     string
    Confidence     float64
    AdditionalData map[string]interface{}
}

type MaintenanceInsightsManager struct {
    encryptionKey       []byte
    logging             bool
    insightStoragePath  string
    insightUpdateFrequency time.Duration
    mutex               sync.Mutex
    insights            map[string]*MaintenanceInsight
}

// NewMaintenanceInsightsManager initializes a new MaintenanceInsightsManager
func NewMaintenanceInsightsManager(encryptionKey string, logging bool, insightStoragePath string, insightUpdateFrequency time.Duration) *MaintenanceInsightsManager {
    return &MaintenanceInsightsManager{
        encryptionKey:       sha256.Sum256([]byte(encryptionKey))[:],
        logging:             logging,
        insightStoragePath:  insightStoragePath,
        insightUpdateFrequency: insightUpdateFrequency,
        insights:            make(map[string]*MaintenanceInsight),
    }
}

// EncryptData encrypts the given data using AES
func (m *MaintenanceInsightsManager) EncryptData(data []byte) (string, error) {
    block, err := aes.NewCipher(m.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptData decrypts the given data using AES
func (m *MaintenanceInsightsManager) DecryptData(encryptedData string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(m.encryptionKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("invalid ciphertext")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// AddInsight adds a new maintenance insight to the manager
func (m *MaintenanceInsightsManager) AddInsight(insight *MaintenanceInsight) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    if _, exists := m.insights[insight.ID]; exists {
        return errors.New("insight already exists")
    }

    m.insights[insight.ID] = insight
    return m.saveInsights()
}

// GetInsight retrieves a maintenance insight by ID
func (m *MaintenanceInsightsManager) GetInsight(id string) (*MaintenanceInsight, error) {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    insight, exists := m.insights[id]
    if !exists {
        return nil, errors.New("insight not found")
    }

    return insight, nil
}

// UpdateInsight updates an existing maintenance insight
func (m *MaintenanceInsightsManager) UpdateInsight(insight *MaintenanceInsight) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    if _, exists := m.insights[insight.ID]; !exists {
        return errors.New("insight not found")
    }

    m.insights[insight.ID] = insight
    return m.saveInsights()
}

// RemoveInsight removes a maintenance insight by ID
func (m *MaintenanceInsightsManager) RemoveInsight(id string) error {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    if _, exists := m.insights[id]; !exists {
        return errors.New("insight not found")
    }

    delete(m.insights, id)
    return m.saveInsights()
}

// ListInsights lists all maintenance insights
func (m *MaintenanceInsightsManager) ListInsights() ([]*MaintenanceInsight, error) {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    insights := make([]*MaintenanceInsight, 0, len(m.insights))
    for _, insight := range m.insights {
        insights = append(insights, insight)
    }

    return insights, nil
}

// saveInsights saves all insights to storage
func (m *MaintenanceInsightsManager) saveInsights() error {
    data, err := json.Marshal(m.insights)
    if err != nil {
        return err
    }

    encryptedData, err := m.EncryptData(data)
    if err != nil {
        return err
    }

    return os.WriteFile(m.insightStoragePath, []byte(encryptedData), 0644)
}

// loadInsights loads all insights from storage
func (m *MaintenanceInsightsManager) loadInsights() error {
    data, err := os.ReadFile(m.insightStoragePath)
    if err != nil {
        return err
    }

    decryptedData, err := m.DecryptData(string(data))
    if err != nil {
        return err
    }

    return json.Unmarshal(decryptedData, &m.insights)
}

// StartInsightUpdateScheduler starts the periodic insight update process
func (m *MaintenanceInsightsManager) StartInsightUpdateScheduler() {
    ticker := time.NewTicker(m.insightUpdateFrequency)
    go func() {
        for {
            <-ticker.C
            m.updateInsights()
        }
    }()
}

// updateInsights updates all insights asynchronously
func (m *MaintenanceInsightsManager) updateInsights() {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    // Update logic for insights can be implemented here
    // For example, refreshing data from external sources or re-calculating predictions
}

