package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"github.com/synthron/synthronchain/crypto"
	"github.com/synthron/synthronchain/utils"
)

// Block represents the fundamental unit in the blockchain.
type Block struct {
	Header       BlockHeader
	Transactions []Transaction
}

// BlockHeader defines the structure for metadata at the top of each block.
type BlockHeader struct {
	PreviousHash []byte
	Timestamp    int64
	Nonce        int64
	MerkleRoot   []byte
}

// Transaction represents a single transaction within the blockchain.
type Transaction struct {
	From     Address
	To       Address
	Value    float64
	Data     []byte
	Signature []byte
}

// Address represents a blockchain address.
type Address string

// SignTransaction signs the transaction with the sender's private key.
func SignTransaction(tx *Transaction, privateKey *ecdsa.PrivateKey) error {
	txDataHash, err := utils.HashTransaction(tx)
	if err != nil {
		return err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, txDataHash)
	if err != nil {
		return err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	tx.Signature = signature
	return nil
}

// VerifyTransaction checks the transaction signature.
func VerifyTransaction(tx Transaction) bool {
	txDataHash, err := utils.HashTransaction(&tx)
	if err != nil {
		return false
	}

	r, s := utils.UnmarshalECDSASignature(tx.Signature)
	pubKey := utils.UnmarshalPublicKey(tx.From)
	return ecdsa.Verify(pubKey, txDataHash, r, s)
}

// CreateBlock generates a new block given transactions and the previous block's hash.
func CreateBlock(transactions []Transaction, previousHash []byte) Block {
	block := Block{
		Header: BlockHeader{
			PreviousHash: previousHash,
			Timestamp:    utils.CurrentTimestamp(),
		},
		Transactions: transactions,
	}
	block.Header.MerkleRoot = utils.CalculateMerkleRoot(transactions)
	return block
}

// ValidateBlock verifies the integrity of a block and its transactions.
func ValidateBlock(block Block) bool {
	computedMerkleRoot := utils.CalculateMerkleRoot(block.Transactions)
	if !utils.CompareHashes(block.Header.MerkleRoot, computedMerkleRoot) {
		return false
	}
	for _, tx := range block.Transactions {
		if !VerifyTransaction(tx) {
			return false
		}
	}
	return true
}

// Additional protocol definitions and cryptographic enhancements can be placed here.

