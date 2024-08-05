package security

import (
	"errors"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// ReversionManager manages the automated reversion of transactions to unsupported contracts.
type ReversionManager struct {
	mu       sync.RWMutex
	ledger   *ledger.Ledger
	logs     []ReversionLog
}

// ReversionLog logs details of reverted transactions.
type ReversionLog struct {
	TransactionID string
	From          string
	To            string
	Amount        uint64
	Reason        string
	Timestamp     int64
}

// NewReversionManager initializes a new ReversionManager instance.
func NewReversionManager(ledger *ledger.Ledger) *ReversionManager {
	return &ReversionManager{
		ledger: ledger,
		logs:   []ReversionLog{},
	}
}

// RevertTransaction reverts a transaction if it is sent to an unsupported contract.
func (rm *ReversionManager) RevertTransaction(txID, from, to string, amount uint64, reason string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Check if the recipient is a valid contract that supports token receiving
	if !rm.isSupportedContract(to) {
		// Reverse the transaction by returning tokens to the sender
		err := rm.ledger.TransferTokens(to, from, amount)
		if err != nil {
			return err
		}

		// Log the reversion
		reversionLog := ReversionLog{
			TransactionID: txID,
			From:          from,
			To:            to,
			Amount:        amount,
			Reason:        reason,
			Timestamp:     utils.GetCurrentTimestamp(),
		}
		rm.logs = append(rm.logs, reversionLog)

		return nil
	}

	return errors.New("transaction recipient is a supported contract")
}

// isSupportedContract checks if a contract address supports token receiving.
func (rm *ReversionManager) isSupportedContract(address string) bool {
	// Implement logic to check if the address is a supported contract
	// This could involve checking a registry of supported contracts
	return false
}

// GetReversionLogs retrieves all reversion logs.
func (rm *ReversionManager) GetReversionLogs() []ReversionLog {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return rm.logs
}

// EncryptReversionLogs encrypts reversion logs using a specified encryption technique.
func (rm *ReversionManager) EncryptReversionLogs(passphrase string) (string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Serialize reversion logs to JSON
	jsonData, err := utils.ToJSON(rm.logs)
	if err != nil {
		return "", err
	}

	// Encrypt JSON data
	encryptedData, err := utils.EncryptData(jsonData, passphrase)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptReversionLogs decrypts reversion logs using a specified decryption technique.
func (rm *ReversionManager) DecryptReversionLogs(encryptedData, passphrase string) ([]ReversionLog, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Decrypt data
	decryptedData, err := utils.DecryptData(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	// Deserialize JSON data to reversion logs
	var logs []ReversionLog
	err = utils.FromJSON(decryptedData, &logs)
	if err != nil {
		return nil, err
	}

	return logs, nil
}
