package peg

import (
    "fmt"
    "time"
    "sync"
    "log"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "io"
    "errors"
    "github.com/synnergy_network_blockchain/pkg/synnergy_network/utils"
)

type AssetStatus struct {
    AssetID       string
    LastChecked   time.Time
    Status        string
    AdditionalInfo map[string]string
}

type RealTimeMonitoring struct {
    monitoredAssets map[string]AssetStatus
    mu              sync.Mutex
    alertChannel    chan string
    aesKey          []byte
}

// NewRealTimeMonitoring creates a new instance of RealTimeMonitoring
func NewRealTimeMonitoring(aesKey string) *RealTimeMonitoring {
    key, err := hex.DecodeString(aesKey)
    if err != nil {
        log.Fatalf("Failed to decode AES key: %v", err)
    }
    return &RealTimeMonitoring{
        monitoredAssets: make(map[string]AssetStatus),
        alertChannel:    make(chan string, 100),
        aesKey:          key,
    }
}

// AddAsset adds an asset to the monitoring list
func (rtm *RealTimeMonitoring) AddAsset(assetID string) {
    rtm.mu.Lock()
    defer rtm.mu.Unlock()
    rtm.monitoredAssets[assetID] = AssetStatus{
        AssetID:       assetID,
        LastChecked:   time.Now(),
        Status:        "OK",
        AdditionalInfo: make(map[string]string),
    }
}

// RemoveAsset removes an asset from the monitoring list
func (rtm *RealTimeMonitoring) RemoveAsset(assetID string) {
    rtm.mu.Lock()
    defer rtm.mu.Unlock()
    delete(rtm.monitoredAssets, assetID)
}

// MonitorAssets continuously monitors the assets
func (rtm *RealTimeMonitoring) MonitorAssets() {
    for {
        rtm.mu.Lock()
        for assetID, status := range rtm.monitoredAssets {
            // Simulated check logic
            newStatus := rtm.checkAssetStatus(assetID)
            if newStatus != status.Status {
                status.Status = newStatus
                status.LastChecked = time.Now()
                rtm.monitoredAssets[assetID] = status
                rtm.alertChannel <- fmt.Sprintf("Asset %s status changed to %s", assetID, newStatus)
            }
        }
        rtm.mu.Unlock()
        time.Sleep(1 * time.Minute) // adjust the monitoring interval as needed
    }
}

// checkAssetStatus simulates checking the asset status
func (rtm *RealTimeMonitoring) checkAssetStatus(assetID string) string {
    // Implement real check logic here
    // For now, returning a random status
    statuses := []string{"OK", "DEGRADED", "FAILED"}
    return statuses[time.Now().Unix()%int64(len(statuses))]
}

// GetAlerts retrieves alerts from the alert channel
func (rtm *RealTimeMonitoring) GetAlerts() <-chan string {
    return rtm.alertChannel
}

// EncryptData encrypts the data using AES
func (rtm *RealTimeMonitoring) EncryptData(plaintext string) (string, error) {
    block, err := aes.NewCipher(rtm.aesKey)
    if err != nil {
        return "", err
    }
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }
    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
    return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the data using AES
func (rtm *RealTimeMonitoring) DecryptData(ciphertext string) (string, error) {
    data, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(rtm.aesKey)
    if err != nil {
        return "", err
    }
    if len(data) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }
    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)
    return string(data), nil
}

// LogMonitoringData logs the monitoring data to the appropriate sink
func (rtm *RealTimeMonitoring) LogMonitoringData() {
    for alert := range rtm.alertChannel {
        log.Printf("ALERT: %s", alert)
        // Additional logging logic can be added here, e.g., sending to a remote server
    }
}

func main() {
    aesKey := "6368616e676520746869732070617373"
    rtm := NewRealTimeMonitoring(aesKey)

    rtm.AddAsset("asset1")
    rtm.AddAsset("asset2")

    go rtm.MonitorAssets()
    go rtm.LogMonitoringData()

    for alert := range rtm.GetAlerts() {
        fmt.Println(alert)
    }
}
