package client

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// MultiSigWallet represents a multi-signature wallet
type MultiSigWallet struct {
    Address    string
    Owners     []string
    Threshold  int
    PendingTxs map[string]*PendingTransaction
    mu         sync.Mutex
}

// PendingTransaction represents a transaction pending approval
type PendingTransaction struct {
    Transaction child_chain.Transaction
    Signatures  map[string]string
}

// NewMultiSigWallet creates a new multi-signature wallet
func NewMultiSigWallet(owners []string, threshold int) (*MultiSigWallet, error) {
    if len(owners) < threshold {
        return nil, errors.New("number of owners must be greater than or equal to the threshold")
    }
    walletAddress := generateMultiSigAddress(owners, threshold)
    return &MultiSigWallet{
        Address:    walletAddress,
        Owners:     owners,
        Threshold:  threshold,
        PendingTxs: make(map[string]*PendingTransaction),
    }, nil
}

// generateMultiSigAddress generates a unique address for the multi-signature wallet
func generateMultiSigAddress(owners []string, threshold int) string {
    record := fmt.Sprintf("%v%d", owners, threshold)
    hash := sha256.New()
    hash.Write([]byte(record))
    return hex.EncodeToString(hash.Sum(nil))
}

// proposeTransaction proposes a new transaction for the multi-signature wallet
func (msw *MultiSigWallet) proposeTransaction(from, to string, amount, fee, nonce int) (string, error) {
    msw.mu.Lock()
    defer msw.mu.Unlock()

    tx, err := child_chain.CreateTransaction(from, to, amount, fee, nonce)
    if err != nil {
        return "", err
    }
    msw.PendingTxs[tx.Hash] = &PendingTransaction{
        Transaction: tx,
        Signatures:  make(map[string]string),
    }
    return tx.Hash, nil
}

// signTransaction allows an owner to sign a proposed transaction
func (msw *MultiSigWallet) signTransaction(txHash, owner, privateKey string) error {
    msw.mu.Lock()
    defer msw.mu.Unlock()

    pendingTx, exists := msw.PendingTxs[txHash]
    if !exists {
        return errors.New("transaction not found")
    }

    if !msw.isOwner(owner) {
        return errors.New("signer is not an owner of the wallet")
    }

    signature, err := signTransaction(pendingTx.Transaction, privateKey)
    if err != nil {
        return err
    }
    pendingTx.Signatures[owner] = signature
    return nil
}

// executeTransaction executes a fully-signed transaction if the threshold is met
func (msw *MultiSigWallet) executeTransaction(txHash string, blockchain *child_chain.Blockchain) error {
    msw.mu.Lock()
    defer msw.mu.Unlock()

    pendingTx, exists := msw.PendingTxs[txHash]
    if !exists {
        return errors.New("transaction not found")
    }

    if len(pendingTx.Signatures) < msw.Threshold {
        return errors.New("not enough signatures to execute the transaction")
    }

    for owner, signature := range pendingTx.Signatures {
        if !verifyTransactionSignature(pendingTx.Transaction, signature, owner) {
            return errors.New("invalid signature from owner: " + owner)
        }
    }

    if err := blockchain.ProcessTransaction(pendingTx.Transaction); err != nil {
        return err
    }

    delete(msw.PendingTxs, txHash)
    return nil
}

// isOwner checks if an address is an owner of the multi-signature wallet
func (msw *MultiSigWallet) isOwner(address string) bool {
    for _, owner := range msw.Owners {
        if owner == address {
            return true
        }
    }
    return false
}
