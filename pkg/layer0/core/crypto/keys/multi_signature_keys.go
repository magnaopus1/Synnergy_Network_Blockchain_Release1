package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// MultiSigWallet represents a multi-signature wallet
type MultiSigWallet struct {
	Keys        []*ecdsa.PrivateKey
	Threshold   int
	Signatures  map[string]*btcec.Signature
	Transaction string
}

// NewMultiSigWallet creates a new instance of a MultiSigWallet
func NewMultiSigWallet(keys []*ecdsa.PrivateKey, threshold int) *MultiSigWallet {
	return &MultiSigWallet{
		Keys:       keys,
		Threshold:  threshold,
		Signatures: make(map[string]*btcec.Signature),
	}
}

// AddSignature adds a signature to the wallet
func (msw *MultiSigWallet) AddSignature(key *ecdsa.PrivateKey, transaction string) error {
	if len(msw.Signatures) >= msw.Threshold {
		return errors.New("threshold already reached, no more signatures needed")
	}

	hash := hashTransaction(transaction)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return err
	}

	sig := &btcec.Signature{R: r, S: s}
	pubKey := key.Public().(*ecdsa.PublicKey)
	msw.Signatures[string(pubKey.X.Bytes())] = sig
	msw.Transaction = transaction

	return nil
}

// VerifySignatures verifies that the collected signatures meet the threshold and are valid
func (msw *MultiSigWallet) VerifySignatures() (bool, error) {
	if len(msw.Signatures) < msw.Threshold {
		return false, fmt.Errorf("insufficient signatures: %d/%d", len(msw.Signatures), msw.Threshold)
	}

	hash := hashTransaction(msw.Transaction)

	for _, sig := range msw.Signatures {
		if !ecdsa.Verify(&ecdsa.PublicKey{
			Curve: btcec.S256(),
			X:     big.NewInt(0).SetBytes(sig.R.Bytes()),
			Y:     big.NewInt(0).SetBytes(sig.S.Bytes()),
		}, hash, sig.R, sig.S) {
			return false, errors.New("signature verification failed")
		}
	}

	return true, nil
}

// hashTransaction simulates hashing of a transaction
func hashTransaction(transaction string) []byte {
	// This is a placeholder for actual transaction hashing logic.
	return []byte(transaction)
}

// Example usage
func main() {
	// Generating keys for demonstration (in practice, use securely stored keys)
	keys := make([]*ecdsa.PrivateKey, 3)
	for i := range keys {
		key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		keys[i] = key
	}

	// Setup a multi-signature wallet with a threshold
	wallet := NewMultiSigWallet(keys, 2)

	// Simulate adding signatures from key holders
	for _, key := range keys[:2] { // Only first two keys sign
		if err := wallet.AddSignature(key, "example_transaction_payload"); err != nil {
			fmt.Printf("Error signing transaction: %v\n", err)
			return
		}
	}

	// Verify if the signatures meet the threshold and are valid
	valid, err := wallet.VerifySignatures()
	if err != nil {
		fmt.Printf("Error verifying signatures: %v\n", err)
		return
	}
	if valid {
		fmt.Println("Transaction is valid with sufficient signatures.")
	} else {
		fmt.Println("Transaction signatures are not sufficient or invalid.")
	}
}

// This module implements a multi-signature wallet where transactions require a minimum number of valid signatures to be executed. It is designed to enhance security by distributing the power of transaction authorization among multiple key holders, thereby reducing the risk associated with single points of failure. The implementation is based on elliptic curve digital signature algorithm (ECDSA) and includes functionalities for adding and verifying signatures to meet specified thresholds.
