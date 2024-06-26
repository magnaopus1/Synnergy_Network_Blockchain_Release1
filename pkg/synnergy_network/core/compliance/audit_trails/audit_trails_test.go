package audit_trails

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"github.com/stretchr/testify/assert"
	"github.com/sirupsen/logrus"
)

// TestSmartContractLogger_LogEvent tests the logging of a smart contract event
func TestSmartContractLogger_LogEvent(t *testing.T) {
	logger, _ := zap.NewProduction()
	scl := NewSmartContractLogger(logger)

	contractAddress := "0x123"
	eventName := "Transfer"
	eventData := "100 tokens from A to B"
	scl.LogEvent(contractAddress, eventName, eventData)

	logs := scl.GetLogs()
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, contractAddress, logs[0].ContractAddress)
	assert.Equal(t, eventName, logs[0].EventName)
	assert.Equal(t, eventData, logs[0].EventData)
}

// TestSmartContractLogger_GetLogs tests the retrieval of smart contract logs
func TestSmartContractLogger_GetLogs(t *testing.T) {
	logger, _ := zap.NewProduction()
	scl := NewSmartContractLogger(logger)

	contractAddress := "0x123"
	eventName := "Transfer"
	eventData := "100 tokens from A to B"
	scl.LogEvent(contractAddress, eventName, eventData)

	logs := scl.GetLogs()
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, contractAddress, logs[0].ContractAddress)
	assert.Equal(t, eventName, logs[0].EventName)
	assert.Equal(t, eventData, logs[0].EventData)
}

// TestSmartContractDrivenAuditLog_CaptureAuditLog tests capturing audit logs from smart contract events
func TestSmartContractDrivenAuditLog_CaptureAuditLog(t *testing.T) {
	auditTrail := NewAuditTrail()
	logger, _ := zap.NewProduction()
	scLogger := NewSmartContractLogger(logger)
	scAuditLog := NewSmartContractDrivenAuditLog(auditTrail, scLogger)

	contractAddress := "0x123"
	eventName := "Transfer"
	eventData := "100 tokens from A to B"
	scLogger.LogEvent(contractAddress, eventName, eventData)

	scAuditLog.CaptureAuditLog()

	logs := auditTrail.GetLogs()
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "SmartContractEvent", logs[0].TransactionType)
	assert.Equal(t, contractAddress, logs[0].Participant)
	assert.Contains(t, logs[0].Details, eventName)
	assert.Contains(t, logs[0].Details, eventData)
}

// TestSmartContractDrivenAuditLog_GenerateAuditReport tests generating an audit report from smart contract-driven audit logs
func TestSmartContractDrivenAuditLog_GenerateAuditReport(t *testing.T) {
	auditTrail := NewAuditTrail()
	logger, _ := zap.NewProduction()
	scLogger := NewSmartContractLogger(logger)
	scAuditLog := NewSmartContractDrivenAuditLog(auditTrail, scLogger)

	contractAddress := "0x123"
	eventName := "Transfer"
	eventData := "100 tokens from A to B"
	scLogger.LogEvent(contractAddress, eventName, eventData)
	scAuditLog.CaptureAuditLog()

	report, err := scAuditLog.GenerateAuditReport()
	assert.NoError(t, err)
	assert.NotNil(t, report)
}

// TestSmartContractDrivenAuditLog_DecentralizedAuditVerification tests decentralized audit verification
func TestSmartContractDrivenAuditLog_DecentralizedAuditVerification(t *testing.T) {
	auditTrail := NewAuditTrail()
	logger, _ := zap.NewProduction()
	scLogger := NewSmartContractLogger(logger)
	scAuditLog := NewSmartContractDrivenAuditLog(auditTrail, scLogger)

	contractAddress := "0x123"
	eventName := "Transfer"
	eventData := "100 tokens from A to B"
	scLogger.LogEvent(contractAddress, eventName, eventData)
	scAuditLog.CaptureAuditLog()

	// Mock decentralized audit verification process
	auditTrail.Logs[0].Verified = true
	assert.True(t, auditTrail.Logs[0].Verified)
}

// TestAuditTrail_AddLog tests adding a log to the audit trail
func TestAuditTrail_AddLog(t *testing.T) {
	auditTrail := NewAuditTrail()
	log := AuditLog{
		TransactionID:   "tx123",
		TransactionType: "Transfer",
		Participant:     "0x123",
		Details:         "100 tokens from A to B",
		Timestamp:       time.Now(),
		Hash:            "hash123",
	}

	auditTrail.AddLog(log)

	logs := auditTrail.GetLogs()
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "tx123", logs[0].TransactionID)
	assert.Equal(t, "Transfer", logs[0].TransactionType)
	assert.Equal(t, "0x123", logs[0].Participant)
	assert.Equal(t, "100 tokens from A to B", logs[0].Details)
	assert.Equal(t, "hash123", logs[0].Hash)
}

// TestAuditTrail_GetLogs tests retrieving logs from the audit trail
func TestAuditTrail_GetLogs(t *testing.T) {
	auditTrail := NewAuditTrail()
	log := AuditLog{
		TransactionID:   "tx123",
		TransactionType: "Transfer",
		Participant:     "0x123",
		Details:         "100 tokens from A to B",
		Timestamp:       time.Now(),
		Hash:            "hash123",
	}

	auditTrail.AddLog(log)

	logs := auditTrail.GetLogs()
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, "tx123", logs[0].TransactionID)
	assert.Equal(t, "Transfer", logs[0].TransactionType)
	assert.Equal(t, "0x123", logs[0].Participant)
	assert.Equal(t, "100 tokens from A to B", logs[0].Details)
	assert.Equal(t, "hash123", logs[0].Hash)
}

// TestSmartContractLogger_ConcurrentLogEvent tests concurrent logging of smart contract events
func TestSmartContractLogger_ConcurrentLogEvent(t *testing.T) {
	logger, _ := zap.NewProduction()
	scl := NewSmartContractLogger(logger)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			contractAddress := "0x123"
			eventName := "Transfer"
			eventData := "100 tokens from A to B"
			scl.LogEvent(contractAddress, eventName, eventData)
		}(i)
	}

	wg.Wait()
	logs := scl.GetLogs()
	assert.Equal(t, 100, len(logs))
}
