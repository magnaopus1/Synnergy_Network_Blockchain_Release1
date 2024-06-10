package financialinstitutions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditTrailLogging tests the ability of the audit trail system to log transactions correctly.
func TestAuditTrailLogging(t *testing.T) {
	at := NewAuditTrail()

	// Simulate logging of multiple transactions
	transactions := []Transaction{
		{ID: "tx1001", Amount: 1000.0, Currency: "USD", Sender: "sender1", Receiver: "receiver1", Time: time.Now()},
		{ID: "tx1002", Amount: 2000.0, Currency: "EUR", Sender: "sender2", Receiver: "receiver2", Time: time.Now().Add(time.Minute)},
		{ID: "tx1003", Amount: 3000.0, Currency: "GBP", Sender: "sender3", Receiver: "receiver3", Time: time.Now().Add(2 * time.Minute)},
	}

	for _, tx := range transactions {
		err := at.LogTransaction(tx)
		assert.Nil(t, err, "Logging transaction should not produce an error")
	}

	// Retrieve the logs
	logs, err := at.GetLogs()
	require.Nil(t, err, "Retrieving logs should not produce an error")
	assert.Len(t, logs, 3, "There should be three logs recorded")

	// Check contents of the logs
	for i, log := range logs {
		assert.Equal(t, transactions[i].ID, log.TransactionID, "Logged transaction ID should match the input transaction ID")
	}
}

// TestAuditTrailIntegrity tests the integrity of the logged data, ensuring no tampering or data loss occurs.
func TestAuditTrailIntegrity(t *testing.T) {
	at := NewAuditTrail()

	// Log a transaction
	tx := Transaction{ID: "tx2001", Amount: 1500.0, Currency: "USD", Sender: "sender4", Receiver: "receiver4", Time: time.Now()}
	err := at.LogTransaction(tx)
	require.Nil(t, err, "Logging transaction should not produce an error")

	// Retrieve the log and verify integrity
	logs, err := at.GetLogs()
	require.Nil(t, err, "Retrieving logs should not produce an error")
	require.Len(t, logs, 1, "There should be exactly one log recorded")

	log := logs[0]
	assert.Equal(t, tx.ID, log.TransactionID, "The transaction ID in the log should match the logged transaction")
	assert.Equal(t, tx.Amount, log.Amount, "The logged amount should match the original transaction")
	assert.Equal(t, tx.Currency, log.Currency, "The logged currency should match the original transaction")
	assert.Equal(t, tx.Sender, log.Sender, "The logged sender should match the original transaction")
	assert.Equal(t, tx.Receiver, log.Receiver, "The logged receiver should match the original transaction")
}

// TestAuditTrailErrorHandling tests the system's ability to handle errors during the logging process.
func TestAuditTrailErrorHandling(t *testing.T) {
	at := NewAuditTrail()

	// Attempt to log an invalid transaction (e.g., negative amount)
	tx := Transaction{ID: "tx3001", Amount: -1000.0, Currency: "USD", Sender: "sender5", Receiver: "receiver5", Time: time.Now()}
	err := at.LogTransaction(tx)
	assert.NotNil(t, err, "Logging an invalid transaction should produce an error")
	assert.Contains(t, err.Error(), "invalid transaction", "The error message should indicate the transaction is invalid")
}

func TestMain(m *testing.M) {
	// Setup and teardown, if necessary
	m.Run()
}
