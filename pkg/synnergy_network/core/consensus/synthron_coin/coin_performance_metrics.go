package synthron_coin

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"
)

// PerformanceMetrics tracks and reports performance metrics for the Synthron blockchain
type PerformanceMetrics struct {
    TotalBlocksMined          int64
    TotalTransactionsProcessed int64
    TotalCoinsMined           int64
    TotalCoinsBurned          int64
    AverageBlockTime          float64
    TotalStakedCoins          int64
    TotalValidators           int64
    TransactionFeesCollected  int64
    BlockTimes                []time.Duration
    mu                        sync.Mutex
}

// NewPerformanceMetrics initializes a new PerformanceMetrics instance
func NewPerformanceMetrics() *PerformanceMetrics {
    return &PerformanceMetrics{
        BlockTimes: make([]time.Duration, 0),
    }
}

// UpdateBlockMined updates the performance metrics when a new block is mined
func (pm *PerformanceMetrics) UpdateBlockMined(coinsMined int64, transactionsProcessed int64, blockTime time.Duration, feesCollected int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pm.TotalBlocksMined++
    pm.TotalCoinsMined += coinsMined
    pm.TotalTransactionsProcessed += transactionsProcessed
    pm.TransactionFeesCollected += feesCollected
    pm.BlockTimes = append(pm.BlockTimes, blockTime)
    pm.AverageBlockTime = pm.calculateAverageBlockTime()
}

// UpdateCoinsBurned updates the performance metrics when coins are burned
func (pm *PerformanceMetrics) UpdateCoinsBurned(coinsBurned int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pm.TotalCoinsBurned += coinsBurned
}

// UpdateStakedCoins updates the performance metrics when coins are staked
func (pm *PerformanceMetrics) UpdateStakedCoins(stakedCoins int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pm.TotalStakedCoins += stakedCoins
}

// UpdateValidators updates the number of validators
func (pm *PerformanceMetrics) UpdateValidators(validators int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    pm.TotalValidators = validators
}

// calculateAverageBlockTime calculates the average time taken to mine blocks
func (pm *PerformanceMetrics) calculateAverageBlockTime() float64 {
    totalDuration := time.Duration(0)
    for _, bt := range pm.BlockTimes {
        totalDuration += bt
    }
    if len(pm.BlockTimes) == 0 {
        return 0
    }
    return totalDuration.Seconds() / float64(len(pm.BlockTimes))
}

// GetHash generates a hash of the current performance metrics for integrity checks
func (pm *PerformanceMetrics) GetHash() string {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    metricsData := struct {
        TotalBlocksMined          int64
        TotalTransactionsProcessed int64
        TotalCoinsMined           int64
        TotalCoinsBurned          int64
        AverageBlockTime          float64
        TotalStakedCoins          int64
        TotalValidators           int64
        TransactionFeesCollected  int64
    }{
        TotalBlocksMined:          pm.TotalBlocksMined,
        TotalTransactionsProcessed: pm.TotalTransactionsProcessed,
        TotalCoinsMined:           pm.TotalCoinsMined,
        TotalCoinsBurned:          pm.TotalCoinsBurned,
        AverageBlockTime:          pm.AverageBlockTime,
        TotalStakedCoins:          pm.TotalStakedCoins,
        TotalValidators:           pm.TotalValidators,
        TransactionFeesCollected:  pm.TransactionFeesCollected,
    }

    hash := sha256.New()
    hash.Write([]byte(fmt.Sprintf("%v", metricsData)))
    return hex.EncodeToString(hash.Sum(nil))
}

// ReportMetrics returns a report of the current performance metrics
func (pm *PerformanceMetrics) ReportMetrics() map[string]interface{} {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    return map[string]interface{}{
        "TotalBlocksMined":          pm.TotalBlocksMined,
        "TotalTransactionsProcessed": pm.TotalTransactionsProcessed,
        "TotalCoinsMined":           pm.TotalCoinsMined,
        "TotalCoinsBurned":          pm.TotalCoinsBurned,
        "AverageBlockTime":          pm.AverageBlockTime,
        "TotalStakedCoins":          pm.TotalStakedCoins,
        "TotalValidators":           pm.TotalValidators,
        "TransactionFeesCollected":  pm.TransactionFeesCollected,
    }
}
