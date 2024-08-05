package channel_core

import (
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/synnergy_network/state_channels/utils/cryptography"
    "github.com/synnergy_network/state_channels/utils/logging"
)

// ChannelMonitor represents the monitoring structure for a state channel.
type ChannelMonitor struct {
    ChannelID     string
    Timeout       time.Duration
    LastActivity  time.Time
    AlertChan     chan string
    StopChan      chan bool
    EncryptionKey []byte
}

var (
    monitors    = make(map[string]*ChannelMonitor)
    monitorsMux sync.Mutex
)

// StartMonitoring initiates the monitoring process for a state channel.
func StartMonitoring(channelID string, timeout time.Duration) {
    monitorsMux.Lock()
    defer monitorsMux.Unlock()

    if _, exists := monitors[channelID]; exists {
        log.Printf("Monitoring already active for channel ID: %s", channelID)
        return
    }

    encryptionKey, err := generateEncryptionKey()
    if err != nil {
        log.Fatalf("Failed to generate encryption key: %v", err)
    }

    monitor := &ChannelMonitor{
        ChannelID:     channelID,
        Timeout:       timeout,
        LastActivity:  time.Now(),
        AlertChan:     make(chan string),
        StopChan:      make(chan bool),
        EncryptionKey: encryptionKey,
    }

    monitors[channelID] = monitor

    go monitor.run()

    logging.Info(fmt.Sprintf("Started monitoring for channel ID: %s", channelID))
}

// StopMonitoring halts the monitoring process for a state channel.
func StopMonitoring(channelID string) {
    monitorsMux.Lock()
    defer monitorsMux.Unlock()

    monitor, exists := monitors[channelID]
    if !exists {
        log.Printf("No active monitoring for channel ID: %s", channelID)
        return
    }

    monitor.StopChan <- true
    delete(monitors, channelID)

    logging.Info(fmt.Sprintf("Stopped monitoring for channel ID: %s", channelID))
}

// UpdateActivity updates the last activity time for the monitored state channel.
func UpdateActivity(channelID string) error {
    monitorsMux.Lock()
    defer monitorsMux.Unlock()

    monitor, exists := monitors[channelID]
    if !exists {
        return fmt.Errorf("no active monitoring for channel ID: %s", channelID)
    }

    monitor.LastActivity = time.Now()
    logging.Info(fmt.Sprintf("Updated activity for channel ID: %s", channelID))

    return nil
}

func (m *ChannelMonitor) run() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            m.checkTimeout()
        case alert := <-m.AlertChan:
            m.handleAlert(alert)
        case <-m.StopChan:
            return
        }
    }
}

func (m *ChannelMonitor) checkTimeout() {
    if time.Since(m.LastActivity) > m.Timeout {
        alert := fmt.Sprintf("Channel ID: %s has timed out", m.ChannelID)
        m.AlertChan <- alert
    }
}

func (m *ChannelMonitor) handleAlert(alert string) {
    encryptedAlert, err := encryptAlert(alert, m.EncryptionKey)
    if err != nil {
        logging.Error(fmt.Sprintf("Failed to encrypt alert for channel ID: %s", m.ChannelID))
        return
    }

    // Log and handle the alert
    logging.Alert(fmt.Sprintf("Alert for channel ID: %s - %s", m.ChannelID, encryptedAlert))
}

// generateEncryptionKey generates a new encryption key for monitoring alerts.
func generateEncryptionKey() ([]byte, error) {
    return cryptography.GenerateKey(32)
}

// encryptAlert encrypts an alert message using AES.
func encryptAlert(alert string, key []byte) (string, error) {
    encrypted, err := cryptography.EncryptAES([]byte(alert), key)
    if err != nil {
        return "", err
    }
    return string(encrypted), nil
}
