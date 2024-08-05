package management

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MultiSigAuthorization manages multi-signature authorizations in the governance model
type MultiSigAuthorization struct {
	Threshold   int
	Signers     map[string]*rsa.PublicKey
	PendingTxns map[string]*MultiSigTransaction
	mutex       sync.Mutex
}

// MultiSigTransaction represents a transaction that requires multi-signature authorization
type MultiSigTransaction struct {
	ID           string
	Data         string
	Signatures   map[string][]byte
	RequiredSigs int
	Timestamp    time.Time
}

// NewMultiSigAuthorization initializes a new MultiSigAuthorization
func NewMultiSigAuthorization(threshold int) *MultiSigAuthorization {
	return &MultiSigAuthorization{
		Threshold:   threshold,
		Signers:     make(map[string]*rsa.PublicKey),
		PendingTxns: make(map[string]*MultiSigTransaction),
	}
}

// AddSigner adds a new signer to the multi-signature authorization system
func (msa *MultiSigAuthorization) AddSigner(signerID string, publicKey *rsa.PublicKey) error {
	msa.mutex.Lock()
	defer msa.mutex.Unlock()

	if _, exists := msa.Signers[signerID]; exists {
		return errors.New("signer already exists")
	}
	msa.Signers[signerID] = publicKey
	return nil
}

// RemoveSigner removes a signer from the multi-signature authorization system
func (msa *MultiSigAuthorization) RemoveSigner(signerID string) error {
	msa.mutex.Lock()
	defer msa.mutex.Unlock()

	if _, exists := msa.Signers[signerID]; !exists {
		return errors.New("signer does not exist")
	}
	delete(msa.Signers, signerID)
	return nil
}

// CreateTransaction creates a new transaction that requires multi-signature authorization
func (msa *MultiSigAuthorization) CreateTransaction(data string, requiredSigs int) (string, error) {
	msa.mutex.Lock()
	defer msa.mutex.Unlock()

	if requiredSigs > msa.Threshold {
		return "", errors.New("required signatures exceed threshold")
	}

	id := generateTransactionID()
	transaction := &MultiSigTransaction{
		ID:           id,
		Data:         data,
		Signatures:   make(map[string][]byte),
		RequiredSigs: requiredSigs,
		Timestamp:    time.Now(),
	}
	msa.PendingTxns[id] = transaction
	return id, nil
}

// SignTransaction allows a signer to sign a transaction
func (msa *MultiSigAuthorization) SignTransaction(txnID, signerID string, privateKey *rsa.PrivateKey) error {
	msa.mutex.Lock()
	defer msa.mutex.Unlock()

	transaction, exists := msa.PendingTxns[txnID]
	if !exists {
		return errors.New("transaction does not exist")
	}

	publicKey, signerExists := msa.Signers[signerID]
	if !signerExists {
		return errors.New("signer not authorized")
	}

	if err := verifyKeyPair(publicKey, privateKey); err != nil {
		return err
	}

	signature, err := signData(privateKey, transaction.Data)
	if err != nil {
		return err
	}
	transaction.Signatures[signerID] = signature

	if len(transaction.Signatures) >= transaction.RequiredSigs {
		delete(msa.PendingTxns, txnID)
	}

	return nil
}

// ListPendingTransactions lists all pending transactions requiring multi-signature authorization
func (msa *MultiSigAuthorization) ListPendingTransactions() []MultiSigTransaction {
	msa.mutex.Lock()
	defer msa.mutex.Unlock()

	transactions := []MultiSigTransaction{}
	for _, txn := range msa.PendingTxns {
		transactions = append(transactions, *txn)
	}
	return transactions
}

// signData signs the given data using the provided private key
func signData(privateKey *rsa.PrivateKey, data string) ([]byte, error) {
	hashed := sha256.Sum256([]byte(data))
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

// verifyKeyPair verifies that the provided public and private keys form a valid pair
func verifyKeyPair(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) error {
	message := []byte("test message")
	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		return err
	}

	decryptedMessage, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedMessage, nil)
	if err != nil {
		return err
	}

	if string(message) != string(decryptedMessage) {
		return errors.New("public and private keys do not match")
	}
	return nil
}

// generateTransactionID generates a unique ID for a transaction
func generateTransactionID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return hex.EncodeToString(id)
}

// MarshalPublicKey converts a public key to a string
func MarshalPublicKey(publicKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pubBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(&pubBlock)), nil
}

// UnmarshalPublicKey converts a string to a public key
func UnmarshalPublicKey(pubKeyStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return publicKey, nil
}
