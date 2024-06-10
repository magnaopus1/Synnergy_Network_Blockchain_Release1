package financialinstitutions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestComplianceCheck tests the enforcement of compliance rules on transactions.
func TestComplianceCheck(t *testing.T) {
	cm := NewComplianceManager()

	// Create a transaction that should pass compliance checks
	tx := Transaction{
		ID:         "tx1001",
		Amount:     5000.00,
		Currency:   "USD",
		Sender:     "valid_sender_wallet_address",
		Receiver:   "valid_receiver_wallet_address",
		Time:       time.Now(),
		Compliance: true,
	}

	// Perform compliance check
	err := cm.CheckCompliance(&tx)
	assert.Nil(t, err, "transaction should pass compliance without errors")

	// Create a transaction that should fail compliance checks
	txNonCompliant := Transaction{
		ID:         "tx1002",
		Amount:     100000.00, // Amount that triggers compliance flags
		Currency:   "USD",
		Sender:     "valid_sender_wallet_address",
		Receiver:   "valid_receiver_wallet_address",
		Time:       time.Now(),
		Compliance: false,
	}

	// Perform compliance check
	err = cm.CheckCompliance(&txNonCompliant)
	assert.NotNil(t, err, "transaction should fail compliance due to high amount")
	assert.Contains(t, err.Error(), "compliance violation", "error message should indicate compliance violation")
}

// TestComplianceReporting tests the reporting functionality of compliance-related incidents.
func TestComplianceReporting(t *testing.T) {
	cm := NewComplianceManager()

	// Simulate a compliance violation
	tx := Transaction{
		ID:         "tx1003",
		Amount:     200000.00, // Amount that triggers compliance flags
		Currency:   "USD",
		Sender:     "valid_sender_wallet_address",
		Receiver:   "valid_receiver_wallet_address",
		Time:       time.Now(),
		Compliance: false,
	}

	cm.CheckCompliance(&tx)
	report := cm.GenerateComplianceReport()

	// Check if the report correctly logs the violation
	assert.Contains(t, report, tx.ID, "report should contain the ID of the non-compliant transaction")
	assert.Contains(t, report, "compliance violation", "report should detail the nature of the violation")
}

// TestComplianceLogHistory tests the logging functionality for tracking compliance checks.
func TestComplianceLogHistory(t *testing.T) {
	cm := NewComplianceManager()

	// Compliance check for multiple transactions
	for i := 0; i < 5; i++ {
		tx := Transaction{
			ID:         "tx200" + string(i),
			Amount:     float64(1000 * i),
			Currency:   "USD",
			Sender:     "sender_wallet_address",
			Receiver:   "receiver_wallet_address",
			Time:       time.Now(),
			Compliance: true,
		}
		cm.CheckCompliance(&tx)
	}

	// Check the log history length
	logHistory := cm.GetComplianceLog()
	assert.Equal(t, 5, len(logHistory), "log history should contain entries for each compliance check")
}

func TestMain(m *testing.M) {
	// Setup and teardown, if necessary
	m.Run()
}
