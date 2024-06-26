package tests

import (
	"testing"
	"time"
	"math/rand"
	"github.com/stretchr/testify/assert"
	"github.com/synthron/synnergy/pkg/layer0/node/optimization_node"
)

func TestTransactionOrderingOptimization(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	transactions := generateMockTransactions(1000)
	start := time.Now()
	orderedTransactions := node.OptimizeTransactionOrdering(transactions)
	duration := time.Since(start)

	assert.Len(t, orderedTransactions, 1000, "Expected 1000 transactions after optimization")
	assert.Less(t, duration.Milliseconds(), int64(100), "Optimization should complete within 100ms")
}

func TestDynamicLoadBalancing(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	loadData := generateMockLoadData(10)
	start := time.Now()
	node.DynamicLoadBalancing(loadData)
	duration := time.Since(start)

	assert.Less(t, duration.Milliseconds(), int64(50), "Load balancing should complete within 50ms")
}

func TestRealTimeDataAnalysis(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	data := generateMockRealTimeData(500)
	start := time.Now()
	analysisResult := node.RealTimeDataAnalysis(data)
	duration := time.Since(start)

	assert.NotNil(t, analysisResult, "Expected a valid analysis result")
	assert.Less(t, duration.Milliseconds(), int64(200), "Real-time analysis should complete within 200ms")
}

func TestAdaptiveAlgorithmicAdjustments(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	historicalData := generateMockHistoricalData(1000)
	start := time.Now()
	node.AdaptiveAlgorithmicAdjustments(historicalData)
	duration := time.Since(start)

	assert.Less(t, duration.Milliseconds(), int64(150), "Adaptive adjustments should complete within 150ms")
}

func TestEncryptionAndDecryption(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	data := []byte("Sensitive optimization data")
	encryptedData, err := node.EncryptData(data)
	assert.NoError(t, err, "Encryption should not produce an error")
	assert.NotEqual(t, data, encryptedData, "Encrypted data should not match the original data")

	decryptedData, err := node.DecryptData(encryptedData)
	assert.NoError(t, err, "Decryption should not produce an error")
	assert.Equal(t, data, decryptedData, "Decrypted data should match the original data")
}

func TestBackupAndRecovery(t *testing.T) {
	node := optimization_node.NewOptimizationNode()

	data := generateMockDataForBackup(1000)
	err := node.CreateBackup(data)
	assert.NoError(t, err, "Backup creation should not produce an error")

	recoveredData, err := node.RecoverFromBackup()
	assert.NoError(t, err, "Recovery should not produce an error")
	assert.Equal(t, data, recoveredData, "Recovered data should match the original data")
}

func generateMockTransactions(count int) []optimization_node.Transaction {
	transactions := make([]optimization_node.Transaction, count)
	for i := 0; i < count; i++ {
		transactions[i] = optimization_node.Transaction{
			ID:        rand.Intn(1000000),
			Timestamp: time.Now().UnixNano(),
			Data:      "Transaction data",
		}
	}
	return transactions
}

func generateMockLoadData(count int) []optimization_node.LoadData {
	loadData := make([]optimization_node.LoadData, count)
	for i := 0; i < count; i++ {
		loadData[i] = optimization_node.LoadData{
			NodeID: rand.Intn(1000),
			Load:   rand.Float64(),
		}
	}
	return loadData
}

func generateMockRealTimeData(count int) []optimization_node.RealTimeData {
	data := make([]optimization_node.RealTimeData, count)
	for i := 0; i < count; i++ {
		data[i] = optimization_node.RealTimeData{
			Timestamp: time.Now().UnixNano(),
			Value:     rand.Float64(),
		}
	}
	return data
}

func generateMockHistoricalData(count int) []optimization_node.HistoricalData {
	historicalData := make([]optimization_node.HistoricalData, count)
	for i := 0; i < count; i++ {
		historicalData[i] = optimization_node.HistoricalData{
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute).UnixNano(),
			Value:     rand.Float64(),
		}
	}
	return historicalData
}

func generateMockDataForBackup(count int) []optimization_node.BackupData {
	data := make([]optimization_node.BackupData, count)
	for i := 0; i < count; i++ {
		data[i] = optimization_node.BackupData{
			Timestamp: time.Now().UnixNano(),
			Data:      "Backup data",
		}
	}
	return data
}
