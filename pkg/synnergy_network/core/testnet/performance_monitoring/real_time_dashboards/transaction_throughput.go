package real_time_dashboards

import (
    "time"
    "log"
    "sync"
    "math/big"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID        string
    Timestamp time.Time
    Size      int64
}

// ThroughputMonitor manages the monitoring of transaction throughput
type ThroughputMonitor struct {
    mu                   sync.Mutex
    transactions         []Transaction
    totalTransactions    int
    totalTransactionSize int64
}

// NewThroughputMonitor initializes a new ThroughputMonitor
func NewThroughputMonitor() *ThroughputMonitor {
    return &ThroughputMonitor{
        transactions: make([]Transaction, 0),
    }
}

// AddTransaction adds a new transaction to the monitor
func (tm *ThroughputMonitor) AddTransaction(tx Transaction) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    tm.transactions = append(tm.transactions, tx)
    tm.totalTransactions++
    tm.totalTransactionSize += tx.Size

    log.Printf("Transaction added: ID=%s, Timestamp=%s, Size=%d bytes\n", tx.ID, tx.Timestamp.String(), tx.Size)
}

// CalculateThroughput calculates the transaction throughput in transactions per second (TPS)
func (tm *ThroughputMonitor) CalculateThroughput(duration time.Duration) (tps float64, bps float64) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    startTime := time.Now().Add(-duration)
    var count int
    var size int64

    for _, tx := range tm.transactions {
        if tx.Timestamp.After(startTime) {
            count++
            size += tx.Size
        }
    }

    elapsed := float64(duration.Seconds())
    tps = float64(count) / elapsed
    bps = float64(size) / elapsed

    log.Printf("Throughput calculated: TPS=%.2f, BPS=%.2f bytes/sec\n", tps, bps)
    return tps, bps
}

// GetStats provides the current transaction statistics
func (tm *ThroughputMonitor) GetStats() (totalTx int, totalSize int64, avgTxSize float64) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    totalTx = tm.totalTransactions
    totalSize = tm.totalTransactionSize
    avgTxSize = float64(totalSize) / float64(totalTx)

    log.Printf("Transaction stats: Total=%d, TotalSize=%d bytes, AvgSize=%.2f bytes\n", totalTx, totalSize, avgTxSize)
    return totalTx, totalSize, avgTxSize
}

// MonitorRealTimeThroughput continuously monitors and logs the transaction throughput
func (tm *ThroughputMonitor) MonitorRealTimeThroughput(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            tm.CalculateThroughput(interval)
        }
    }
}

// TransactionAnomalyDetector detects anomalies in transaction throughput
type TransactionAnomalyDetector struct {
    thresholdTPS float64
    thresholdBPS float64
    monitor      *ThroughputMonitor
}

// NewTransactionAnomalyDetector initializes a new TransactionAnomalyDetector
func NewTransactionAnomalyDetector(thresholdTPS float64, thresholdBPS float64, monitor *ThroughputMonitor) *TransactionAnomalyDetector {
    return &TransactionAnomalyDetector{
        thresholdTPS: thresholdTPS,
        thresholdBPS: thresholdBPS,
        monitor:      monitor,
    }
}

// DetectAnomalies checks for anomalies in the transaction throughput
func (tad *TransactionAnomalyDetector) DetectAnomalies(duration time.Duration) {
    tps, bps := tad.monitor.CalculateThroughput(duration)
    if tps > tad.thresholdTPS {
        log.Printf("Anomaly detected: TPS=%.2f exceeds threshold=%.2f\n", tps, tad.thresholdTPS)
    }
    if bps > tad.thresholdBPS {
        log.Printf("Anomaly detected: BPS=%.2f bytes/sec exceeds threshold=%.2f bytes/sec\n", bps, tad.thresholdBPS)
    }
}

// SecureTransaction secures a transaction using Argon2 for hashing
func SecureTransaction(data []byte, salt []byte) ([]byte, error) {
    // Argon2 hashing implementation
    hashed := argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
    return hashed, nil
}

// EncryptData encrypts data using AES
func EncryptData(plainText []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    cipherText := gcm.Seal(nonce, nonce, plainText, nil)
    return cipherText, nil
}

// DecryptData decrypts AES encrypted data
func DecryptData(cipherText []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

    plainText, err := gcm.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return nil, err
    }

    return plainText, nil
}

