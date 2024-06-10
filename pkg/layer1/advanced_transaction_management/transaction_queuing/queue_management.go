package transaction_queuing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID        string
	Data      []byte // Encrypted transaction data
	Timestamp int64
}

// TransactionQueue represents a secure queue for managing transactions
type TransactionQueue struct {
	queue []Transaction
	lock  sync.Mutex
}

// NewTransactionQueue creates a new transaction queue
func NewTransactionQueue() *TransactionQueue {
	return &TransactionQueue{
		queue: make([]Transaction, 0),
	}
}

// Enqueue adds a new transaction to the queue
func (tq *TransactionQueue) Enqueue(tx Transaction) {
	tq.lock.Lock()
	defer tq.lock.Unlock()
	tq.queue = append(tq.queue, tx)
}

// Dequeue removes and returns the first transaction in the queue
func (tq *TransactionQueue) Dequeue() (Transaction, error) {
	tq.lock.Lock()
	defer tq.lock.Unlock()
	if len(tq.queue) == 0 {
		return Transaction{}, errors.New("queue is empty")
	}
	tx := tq.queue[0]
	tq.queue = tq.queue[1:]
	return tx, nil
}

// EncryptData encrypts transaction data using AES
func EncryptData(data []byte, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	b := make([]byte, aes.BlockSize+len(data))
	iv := b[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(b[aes.BlockSize:], data)
	return hex.EncodeToString(b), nil
}

// DecryptData decrypts transaction data using AES
func DecryptData(ciphertext string, key string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

// Size returns the current size of the queue
func (tq *TransactionQueue) Size() int {
	tq.lock.Lock()
	defer tq.lock.Unlock()
	return len(tq.queue)
}
