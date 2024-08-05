package node

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "math/big"
    "sync"

    "github.com/synnergy_network_blockchain/plasma/child_chain"
)

// Node represents a node in the blockchain network
type Node struct {
    Blockchain       []Block
    Nodes            map[string]*Node
    PendingTxns      []child_chain.Transaction
    Consensus        string
    Difficulty       int
    mu               sync.Mutex
    NodeID           string
    Stake            int
    ValidatorSet     map[string]int
    ValidatorAddress string
    Address          string
    Port             string
}

// GenerateKeyPair generates a new ECDSA key pair
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return priv, &priv.PublicKey, nil
}

// SignTransaction signs a transaction using a private key
func SignTransaction(tx *child_chain.Transaction, privKey *ecdsa.PrivateKey) (string, error) {
    txHash := sha256.Sum256([]byte(tx.ToString()))
    r, s, err := ecdsa.Sign(rand.Reader, privKey, txHash[:])
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(r.Bytes()) + hex.EncodeToString(s.Bytes()), nil
}

// VerifyTransaction verifies a transaction's signature
func VerifyTransaction(tx *child_chain.Transaction, pubKey *ecdsa.PublicKey, signature string) (bool, error) {
    sigBytes, err := hex.DecodeString(signature)
    if err != nil {
        return false, err
    }
    if len(sigBytes) != 64 {
        return false, errors.New("invalid signature length")
    }
    r := big.Int{}
    s := big.Int{}
    r.SetBytes(sigBytes[:32])
    s.SetBytes(sigBytes[32:])
    txHash := sha256.Sum256([]byte(tx.ToString()))
    return ecdsa.Verify(pubKey, txHash[:], &r, &s), nil
}

// ValidateTransaction checks if a transaction is valid
func (n *Node) ValidateTransaction(tx *child_chain.Transaction) error {
    if !tx.IsValid() {
        return errors.New("invalid transaction")
    }

    pubKey, err := tx.GetPublicKey()
    if err != nil {
        return err
    }

    valid, err := VerifyTransaction(tx, pubKey, tx.Signature)
    if err != nil {
        return err
    }
    if !valid {
        return errors.New("invalid transaction signature")
    }

    return nil
}

// VerifyAndAddTransaction verifies and adds a transaction to the pending transactions pool
func (n *Node) VerifyAndAddTransaction(tx *child_chain.Transaction) error {
    if err := n.ValidateTransaction(tx); err != nil {
        return err
    }

    n.mu.Lock()
    defer n.mu.Unlock()

    n.PendingTxns = append(n.PendingTxns, tx)
    return nil
}

// ValidateBlockTransactions verifies all transactions in a block
func (n *Node) ValidateBlockTransactions(block *Block) error {
    for _, tx := range block.Transactions {
        if err := n.ValidateTransaction(&tx); err != nil {
            return err
        }
    }
    return nil
}

// AddBlock adds a validated block to the blockchain
func (n *Node) AddBlock(block *Block) error {
    if err := n.ValidateBlockTransactions(block); err != nil {
        return err
    }

    n.mu.Lock()
    defer n.mu.Unlock()

    n.Blockchain = append(n.Blockchain, *block)
    return nil
}
