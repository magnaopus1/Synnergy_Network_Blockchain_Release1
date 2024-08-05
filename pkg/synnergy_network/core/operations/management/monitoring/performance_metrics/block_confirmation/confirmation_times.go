package performance_metrics

import (
    "fmt"
    "time"
    "sync"
    "math"
    "encoding/json"
    "github.com/synnergy_network/pkg/utils"
    "github.com/synnergy_network/pkg/blockchain"
    "github.com/synnergy_network/pkg/encryption"
)

// BlockConfirmationMetrics holds metrics related to block confirmation times.
type BlockConfirmationMetrics struct {
    sync.Mutex
    confirmations map[string][]time.Duration
    averageTimes  map[string]time.Duration
    encryptedData map[string]string
}

// NewBlockConfirmationMetrics initializes a new BlockConfirmationMetrics instance.
func NewBlockConfirmationMetrics() *BlockConfirmationMetrics {
    return &BlockConfirmationMetrics{
        confirmations: make(map[string][]time.Duration),
        averageTimes:  make(map[string]time.Duration),
        encryptedData: make(map[string]string),
    }
}

// RecordConfirmation records the time taken to confirm a block.
func (b *BlockConfirmationMetrics) RecordConfirmation(blockID string, confirmationTime time.Duration) {
    b.Lock()
    defer b.Unlock()

    b.confirmations[blockID] = append(b.confirmations[blockID], confirmationTime)
    b.calculateAverageTime(blockID)
}

// calculateAverageTime calculates the average confirmation time for a block.
func (b *BlockConfirmationMetrics) calculateAverageTime(blockID string) {
    times := b.confirmations[blockID]
    total := time.Duration(0)
    for _, t := range times {
        total += t
    }
    b.averageTimes[blockID] = total / time.Duration(len(times))
}

// GetAverageTime returns the average confirmation time for a block.
func (b *BlockConfirmationMetrics) GetAverageTime(blockID string) time.Duration {
    b.Lock()
    defer b.Unlock()
    return b.averageTimes[blockID]
}

// EncryptData encrypts the confirmation data for security.
func (b *BlockConfirmationMetrics) EncryptData(password string) error {
    b.Lock()
    defer b.Unlock()

    data, err := json.Marshal(b.confirmations)
    if err != nil {
        return fmt.Errorf("failed to marshal data: %v", err)
    }

    encryptedData, err := encryption.EncryptData(data, password)
    if err != nil {
        return fmt.Errorf("failed to encrypt data: %v", err)
    }

    b.encryptedData["confirmations"] = encryptedData
    return nil
}

// DecryptData decrypts the confirmation data.
func (b *BlockConfirmationMetrics) DecryptData(password string) error {
    b.Lock()
    defer b.Unlock()

    encryptedData, ok := b.encryptedData["confirmations"]
    if !ok {
        return fmt.Errorf("no encrypted data found")
    }

    decryptedData, err := encryption.DecryptData(encryptedData, password)
    if err != nil {
        return fmt.Errorf("failed to decrypt data: %v", err)
    }

    var confirmations map[string][]time.Duration
    err = json.Unmarshal(decryptedData, &confirmations)
    if err != nil {
        return fmt.Errorf("failed to unmarshal data: %v", err)
    }

    b.confirmations = confirmations
    for blockID := range b.confirmations {
        b.calculateAverageTime(blockID)
    }
    return nil
}

// ReportConfirmationMetrics generates a report of the confirmation metrics.
func (b *BlockConfirmationMetrics) ReportConfirmationMetrics() (string, error) {
    b.Lock()
    defer b.Unlock()

    report := struct {
        Confirmations map[string][]time.Duration `json:"confirmations"`
        Averages      map[string]time.Duration   `json:"average_times"`
    }{
        Confirmations: b.confirmations,
        Averages:      b.averageTimes,
    }

    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return "", fmt.Errorf("failed to marshal report: %v", err)
    }

    return string(data), nil
}

// GetConfirmationStatistics calculates and returns statistics for block confirmations.
func (b *BlockConfirmationMetrics) GetConfirmationStatistics() (map[string]map[string]float64, error) {
    b.Lock()
    defer b.Unlock()

    stats := make(map[string]map[string]float64)
    for blockID, times := range b.confirmations {
        if len(times) == 0 {
            continue
        }

        sum := float64(0)
        for _, t := range times {
            sum += float64(t)
        }
        mean := sum / float64(len(times))

        varianceSum := float64(0)
        for _, t := range times {
            varianceSum += math.Pow(float64(t)-mean, 2)
        }
        variance := varianceSum / float64(len(times))
        stdDev := math.Sqrt(variance)

        stats[blockID] = map[string]float64{
            "mean":    mean,
            "std_dev": stdDev,
            "variance": variance,
        }
    }

    return stats, nil
}

// MonitorConfirmationTimes continuously monitors and records block confirmation times.
func (b *BlockConfirmationMetrics) MonitorConfirmationTimes(blockchain *blockchain.Blockchain, interval time.Duration) {
    for {
        blockID, confirmationTime := blockchain.GetLatestBlockConfirmationTime()
        b.RecordConfirmation(blockID, confirmationTime)
        time.Sleep(interval)
    }
}

