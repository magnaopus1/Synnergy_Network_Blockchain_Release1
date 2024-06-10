package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/gob"
	"errors"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/argon2"
)

// Ledger represents the blockchain ledger for storing and managing transactions.
type Ledger struct {
	db          *leveldb.DB
	lock        sync.RWMutex
	encryptionKey []byte
}

// Transaction represents the data structure for a blockchain transaction.
type Transaction struct {
	ID        []byte
	Timestamp int64
	Data      []byte
	Hash      []byte
	Signature []byte
}

// NewLedger initializes a new ledger with the specified path and encryption key.
func NewLedger(path string, key string) (*Ledger, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}

	// Generate encryption key from passphrase using Argon2
	salt := []byte("blockchain_salt")
	argonKey := argon2.IDKey([]byte(key), salt, 1, 64*1024, 4, 32)

	return &Ledger{
		db:           db,
		encryptionKey: argonKey,
	}, nil
}

// AddTransaction encrypts and stores a new transaction in the ledger.
func (l *Ledger) AddTransaction(tx *Transaction) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	encoded, err := encodeTransaction(tx)
	if err != nil {
		return err
	}

	encrypted, err := l.encryptData(encoded)
	if err != nil {
		return err
	}

	return l.db.Put(tx.ID, encrypted, nil)
}

// GetTransaction retrieves and decrypts a transaction from the ledger.
func (l *Ledger) GetTransaction(id []byte) (*Transaction, error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	encrypted, err := l.db.Get(id, nil)
	if err != nil {
		return nil, err
	}

	decoded, err := l.decryptData(encrypted)
	if err != nil {
		return nil, err
	}

	return decodeTransaction(decoded)
}

// encodeTransaction serializes a Transaction using Gob encoder.
func encodeTransaction(tx *Transaction) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(tx)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// decodeTransaction deserializes a Transaction using Gob decoder.
func decodeTransaction(data []byte) (*Transaction, error) {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	tx := &Transaction{}
	err := decoder.Decode(tx)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// encryptData encrypts data using AES.
func (l *Ledger) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptData decrypts data using AES.
func (l *Ledger) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(l.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceX
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Close safely closes the database connection.
func (l *Ledger) Close() error {
	return l.db.Close()
}
