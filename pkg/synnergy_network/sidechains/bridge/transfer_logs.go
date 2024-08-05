package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// TransferLog represents the details of a transfer log entry
type TransferLog struct {
	TransactionID string    `json:"transaction_id"`
	FromChainID   string    `json:"from_chain_id"`
	ToChainID     string    `json:"to_chain_id"`
	FromAddress   string    `json:"from_address"`
	ToAddress     string    `json:"to_address"`
	TokenAmount   float64   `json:"token_amount"`
	Status        string    `json:"status"`
	Timestamp     time.Time `json:"timestamp"`
	Signature     string    `json:"signature"`
}

// TransferLogManager handles logging for asset transfers
type TransferLogManager struct {
	logFilePath string
	logs        map[string]*TransferLog
}

// NewTransferLogManager creates a new TransferLogManager
func NewTransferLogManager(logFilePath string) *TransferLogManager {
	return &TransferLogManager{
		logFilePath: logFilePath,
		logs:        make(map[string]*TransferLog),
	}
}

// LogTransfer logs a new transfer
func (tlm *TransferLogManager) LogTransfer(transactionID, fromChainID, toChainID, fromAddress, toAddress string, tokenAmount float64, status, signature string) error {
	timestamp := time.Now()
	transferLog := &TransferLog{
		TransactionID: transactionID,
		FromChainID:   fromChainID,
		ToChainID:     toChainID,
		FromAddress:   fromAddress,
		ToAddress:     toAddress,
		TokenAmount:   tokenAmount,
		Status:        status,
		Timestamp:     timestamp,
		Signature:     signature,
	}

	// Add to in-memory log
	tlm.logs[transactionID] = transferLog

	// Append to file
	return tlm.appendLogToFile(transferLog)
}

// appendLogToFile appends a transfer log to the log file
func (tlm *TransferLogManager) appendLogToFile(transferLog *TransferLog) error {
	file, err := os.OpenFile(tlm.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	logData, err := json.Marshal(transferLog)
	if err != nil {
		return err
	}

	if _, err = file.WriteString(fmt.Sprintf("%s\n", logData)); err != nil {
		return err
	}

	return nil
}

// GetTransferLog retrieves a transfer log by transaction ID
func (tlm *TransferLogManager) GetTransferLog(transactionID string) (*TransferLog, error) {
	transferLog, exists := tlm.logs[transactionID]
	if !exists {
		return nil, errors.New("transfer log not found")
	}
	return transferLog, nil
}

// ListTransferLogs lists all transfer logs
func (tlm *TransferLogManager) ListTransferLogs() ([]*TransferLog, error) {
	var transferLogs []*TransferLog
	for _, log := range tlm.logs {
		transferLogs = append(transferLogs, log)
	}
	return transferLogs, nil
}

// LoadLogsFromFile loads transfer logs from the log file
func (tlm *TransferLogManager) LoadLogsFromFile() error {
	file, err := os.Open(tlm.logFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var transferLog TransferLog
		if err := decoder.Decode(&transferLog); err != nil {
			break
		}
		tlm.logs[transferLog.TransactionID] = &transferLog
	}

	return nil
}

// VerifyTransferLog verifies the integrity of a transfer log entry
func (tlm *TransferLogManager) VerifyTransferLog(transactionID, signature string) (bool, error) {
	transferLog, exists := tlm.logs[transactionID]
	if !exists {
		return false, errors.New("transfer log not found")
	}

	return transferLog.Signature == signature, nil
}
