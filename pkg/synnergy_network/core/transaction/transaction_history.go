package transaction

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"io"
	"sync"
	"time"
)

// ArchiveTransactionHistory archives transaction history at regular intervals
func (ha *common.HistoryArchival) ArchiveTransactionHistory(transactions []common.Transaction) error {
	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	if len(transactions) == 0 {
		return errors.New("no transactions to archive")
	}

	data, err := Serialize(transactions)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptAES(data, ha.encryptionKey)
	if err != nil {
		return err
	}

	err = ha.storage.Store(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// RetrieveArchivedHistory retrieves archived transaction history
func (ha *common.HistoryArchival) RetrieveArchivedTransactionHistory(timestamp time.Time) ([]common.Transaction, error) {
	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	encryptedData, err := ha.storage.Retrieve(timestamp)
	if err != nil {
		return nil, err
	}

	data, err := DecryptAES(encryptedData, ha.encryptionKey)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	err = Deserialize(data, &transactions)
	if err != nil {
		return nil, err
	}

	return transactions, nil
}

// ScheduleArchival schedules regular archival of transaction history
func (ha *common.HistoryArchival) ScheduleTransactionArchival(transactions []common.Transaction) {
	ticker := time.NewTicker(ha.archiveInterval)
	go func() {
		for range ticker.C {
			err := ha.ArchiveTransactionHistory(transactions)
			if err != nil {
				// Log the error (implement logging based on your system's logging mechanism)
			}
		}
	}()
}

// SecureTransmission handles the secure transmission of archived data
func (ha *common.HistoryArchival) SecureTransmissionOfArchivedData(data []byte, key []byte) ([]byte, error) {
	return EncryptAES(data, key)
}

// ProcessReceivedData handles the processing of received encrypted archived data
func (ha *common.HistoryArchival) ProcessReceivedArchivedData(encryptedData []byte, key []byte) ([]byte, error) {
	return DecryptAES(encryptedData, key)
}

// DeleteArchivedHistory deletes archived transaction history based on retention policies
func (ha *common.HistoryArchival) DeleteArchivedTransactionHistory(timestamp time.Time) error {
	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	err := ha.storage.Delete(timestamp)
	if err != nil {
		return err
	}

	return nil
}

// AddTransaction adds a transaction to the history
func (th *common.TransactionHistory) AddTransactionToHistory(tx common.Transaction) error {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	data, err := Serialize(tx)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptAES(data, th.encryptionKey)
	if err != nil {
		return err
	}

	err = th.storage.Store(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// GetTransaction retrieves a transaction from the history by its ID
func (th *common.TransactionHistory) GetTransactionFromHistory(txID string) (*common.Transaction, error) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	encryptedData, err := th.storage.Retrieve(txID)
	if err != nil {
		return nil, err
	}

	data, err := DecryptAES(encryptedData, th.encryptionKey)
	if err != nil {
		return nil, err
	}

	var tx common.Transaction
	err = Deserialize(data, &tx)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}

// DeleteTransaction removes a transaction from the history
func (th *common.TransactionHistory) DeleteTransactionFromHistory(txID string) error {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	err := th.storage.Delete(txID)
	if err != nil {
		return err
	}

	return nil
}

// ListTransactions lists all transactions within a specific time range
func (th *common.TransactionHistory) ListAllTransactionsWithinTimeRange(startTime, endTime time.Time) ([]common.Transaction, error) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	encryptedDataList, err := th.storage.ListByTimeRange(startTime, endTime)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	for _, encryptedData := range encryptedDataList {
		data, err := DecryptAES(encryptedData, th.encryptionKey)
		if err != nil {
			return nil, err
		}

		var tx common.Transaction
		err = Deserialize(data, &tx)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// SearchByID retrieves a transaction by its ID
func (ts *common.TransactionSearch) SearchTransactionByID(txID string) (*common.Transaction, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	encryptedData, err := ts.storage.Retrieve(txID)
	if err != nil {
		return nil, err
	}

	data, err := DecryptAES(encryptedData, ts.encryptionKey)
	if err != nil {
		return nil, err
	}

	var tx common.Transaction
	err = Deserialize(data, &tx)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}

// SearchByTimestamp retrieves transactions within a specific time range
func (ts *common.TransactionSearch) SearchTransactionByTimestamp(startTime, endTime time.Time) ([]common.Transaction, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	encryptedDataList, err := ts.storage.ListByTimeRange(startTime, endTime)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	for _, encryptedData := range encryptedDataList {
		data, err := DecryptAES(encryptedData, ts.encryptionKey)
		if err != nil {
			return nil, err
		}

		var tx common.Transaction
		err = Deserialize(data, &tx)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// SearchBySender retrieves transactions by the sender's address
func (ts *common.TransactionSearch) SearchTransactionBySender(senderAddress string) ([]common.Transaction, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	encryptedDataList, err := ts.storage.ListByField("sender", senderAddress)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	for _, encryptedData := range encryptedDataList {
		data, err := DecryptAES(encryptedData, ts.encryptionKey)
		if err != nil {
			return nil, err
		}

		var tx common.Transaction
		err = Deserialize(data, &tx)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// SearchByReceiver retrieves transactions by the receiver's address
func (ts *common.TransactionSearch) SearchTransactionByReceiver(receiverAddress string) ([]common.Transaction, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	encryptedDataList, err := ts.storage.ListByField("receiver", receiverAddress)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	for _, encryptedData := range encryptedDataList {
		data, err := DecryptAES(encryptedData, ts.encryptionKey)
		if err != nil {
			return nil, err
		}

		var tx common.Transaction
		err = Deserialize(data, &tx)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// SearchByAmountRange retrieves transactions within a specific amount range
func (ts *common.TransactionSearch) SearchTransactionByAmountRange(minAmount, maxAmount float64) ([]common.Transaction, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	encryptedDataList, err := ts.storage.ListByAmountRange(minAmount, maxAmount)
	if err != nil {
		return nil, err
	}

	var transactions []common.Transaction
	for _, encryptedData := range encryptedDataList {
		data, err := DecryptAES(encryptedData, ts.encryptionKey)
		if err != nil {
			return nil, err
		}

		var tx common.Transaction
		err = Deserialize(data, &tx)
		if err != nil {
			return nil, err
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}
