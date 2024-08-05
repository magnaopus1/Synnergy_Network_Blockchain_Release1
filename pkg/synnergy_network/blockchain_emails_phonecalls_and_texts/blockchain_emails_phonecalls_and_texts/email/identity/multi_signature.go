package identity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// MultiSigWallet represents a multi-signature wallet
type MultiSigWallet struct {
	Owners        map[string]*ecdsa.PrivateKey
	RequiredSigs  int
	PendingTxs    map[string]*Transaction
	ConfirmedTxs  map[string]*Transaction
}

// Transaction represents a transaction to be signed by multiple parties
type Transaction struct {
	ID            string
	To            string
	Value         int64
	Data          string
	Signatures    map[string]string
	Confirmations int
	CreatedAt     time.Time
}

// NewMultiSigWallet creates a new multi-signature wallet
func NewMultiSigWallet(requiredSigs int, owners ...*ecdsa.PrivateKey) (*MultiSigWallet, error) {
	if requiredSigs > len(owners) {
		return nil, errors.New("required signatures cannot exceed the number of owners")
	}

	ownerMap := make(map[string]*ecdsa.PrivateKey)
	for _, owner := range owners {
		address := crypto.PubkeyToAddress(owner.PublicKey).Hex()
		ownerMap[address] = owner
	}

	return &MultiSigWallet{
		Owners:       ownerMap,
		RequiredSigs: requiredSigs,
		PendingTxs:   make(map[string]*Transaction),
		ConfirmedTxs: make(map[string]*Transaction),
	}, nil
}

// CreateTransaction creates a new transaction
func (wallet *MultiSigWallet) CreateTransaction(to string, value int64, data string) (*Transaction, error) {
	txID, err := generateTxID()
	if err != nil {
		return nil, err
	}

	tx := &Transaction{
		ID:         txID,
		To:         to,
		Value:      value,
		Data:       data,
		Signatures: make(map[string]string),
		CreatedAt:  time.Now(),
	}

	wallet.PendingTxs[txID] = tx
	return tx, nil
}

// SignTransaction allows an owner to sign a transaction
func (wallet *MultiSigWallet) SignTransaction(owner *ecdsa.PrivateKey, txID string) (string, error) {
	tx, exists := wallet.PendingTxs[txID]
	if !exists {
		return "", errors.New("transaction does not exist")
	}

	address := crypto.PubkeyToAddress(owner.PublicKey).Hex()
	if _, isOwner := wallet.Owners[address]; !isOwner {
		return "", errors.New("only wallet owners can sign transactions")
	}

	hash := sha256.Sum256([]byte(txID + tx.To + fmt.Sprint(tx.Value) + tx.Data))
	signature, err := crypto.Sign(hash[:], owner)
	if err != nil {
		return "", err
	}

	sigHex := hex.EncodeToString(signature)
	tx.Signatures[address] = sigHex
	tx.Confirmations++

	if tx.Confirmations >= wallet.RequiredSigs {
		wallet.ConfirmedTxs[txID] = tx
		delete(wallet.PendingTxs, txID)
	}

	return sigHex, nil
}

// VerifyTransaction verifies if a transaction has enough signatures
func (wallet *MultiSigWallet) VerifyTransaction(txID string) (bool, error) {
	tx, exists := wallet.ConfirmedTxs[txID]
	if !exists {
		return false, errors.New("transaction does not exist")
	}

	if tx.Confirmations >= wallet.RequiredSigs {
		return true, nil
	}

	return false, nil
}

// ExecuteTransaction executes a confirmed transaction
func (wallet *MultiSigWallet) ExecuteTransaction(txID string) error {
	tx, exists := wallet.ConfirmedTxs[txID]
	if !exists {
		return errors.New("transaction does not exist or is not confirmed")
	}

	// Add logic to execute the transaction (e.g., transfer funds, execute smart contract)
	// For this example, we'll just print the transaction details
	fmt.Printf("Executing transaction %s: to %s, value %d, data %s\n", tx.ID, tx.To, tx.Value, tx.Data)

	delete(wallet.ConfirmedTxs, txID)
	return nil
}

// generateTxID generates a unique transaction ID
func generateTxID() (string, error) {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id), nil
}
