package consensus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

// Setup function to initialize the ProofOfWork system for testing
func setupProofOfWork() *ProofOfWork {
	difficulty := 2
	blockReward := big.NewInt(50)
	halvingInterval := 10
	minerConfig := &common.MinerConfig{
		Algorithm:  "sha256",
		Iterations: 1,
		Memory:     1024,
		Parallelism: 1,
		KeyLength:  32,
	}

	publicKeyProvider := DefaultPublicKeyProvider
	coinManager := NewCoinManager()

	return NewProofOfWork(difficulty, blockReward, halvingInterval, minerConfig, publicKeyProvider, coinManager)
}

// Test CalculateBlockHash function
func TestCalculateBlockHash(t *testing.T) {
	pow := setupProofOfWork()
	block := &common.Block{
		Timestamp:    time.Now().Unix(),
		Transactions: []*common.Transaction{},
		PrevBlockHash: "previousHash",
	}

	hash, err := pow.CalculateBlockHash(block)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
}

// Test ValidateBlockHash function
func TestValidateBlockHash(t *testing.T) {
	pow := setupProofOfWork()
	block := &common.Block{
		Timestamp:    time.Now().Unix(),
		Transactions: []*common.Transaction{},
		PrevBlockHash: "previousHash",
	}

	hash, err := pow.CalculateBlockHash(block)
	assert.NoError(t, err)

	isValid := pow.ValidateBlockHash(hash)
	assert.True(t, isValid)
}

// Test AddTransaction function
func TestAddTransaction(t *testing.T) {
	pow := setupProofOfWork()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	tx := &common.Transaction{
		ID:       "tx1",
		Sender:   "Alice",
		Receiver: "Bob",
		Amount:   big.NewInt(10),
		Fee:      big.NewInt(1),
		Signature: signTransaction(privateKey, "Alice", "Bob", big.NewInt(10), big.NewInt(1)),
	}

	err = AddTransaction(tx)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(pow.TransactionPool))
}

// Test ProcessTransactions function
func TestProcessTransactions(t *testing.T) {
	pow := setupProofOfWork()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	txs := []*common.Transaction{
		{
			ID:       "tx1",
			Sender:   "Alice",
			Receiver: "Bob",
			Amount:   big.NewInt(10),
			Fee:      big.NewInt(1),
			Signature: signTransaction(privateKey, "Alice", "Bob", big.NewInt(10), big.NewInt(1)),
		},
		{
			ID:       "tx2",
			Sender:   "Bob",
			Receiver: "Charlie",
			Amount:   big.NewInt(5),
			Fee:      big.NewInt(1),
			Signature: signTransaction(privateKey, "Bob", "Charlie", big.NewInt(5), big.NewInt(1)),
		},
	}

	err = pow.ProcessTransactions(txs)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(pow.TransactionPool))
}

// Test MineBlock function
func TestMineBlock(t *testing.T) {
	pow := setupProofOfWork()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	tx := &Transaction{
		ID:       "tx1",
		Sender:   "Alice",
		Receiver: "Bob",
		Amount:   big.NewInt(10),
		Fee:      big.NewInt(1),
		Signature: signTransaction(privateKey, "Alice", "Bob", big.NewInt(10), big.NewInt(1)),
	}

	err = pow.AddTransaction(tx)
	assert.NoError(t, err)

	block, err := pow.MineBlock()
	assert.NoError(t, err)
	assert.NotEmpty(t, block.Hash)
}

// Test AdjustDifficulty function
func TestAdjustDifficulty(t *testing.T) {
	pow := setupProofOfWork()
	previousDifficulty := pow.Difficulty

	pow.Blockchain = append(pow.Blockchain, &common.Block{Timestamp: time.Now().Unix() - 1000})
	pow.Blockchain = append(pow.Blockchain, &common.Block{Timestamp: time.Now().Unix()})

	pow.adjustDifficulty()
	assert.NotEqual(t, previousDifficulty, pow.Difficulty)
}

// Test AdjustBlockReward function
func TestAdjustBlockReward(t *testing.T) {
	pow := setupProofOfWork()
	previousBlockReward := new(big.Int).Set(pow.BlockReward)

	pow.Blockchain = append(pow.Blockchain, &common.Block{})
	pow.Blockchain = append(pow.Blockchain, &common.Block{})

	pow.adjustBlockReward()
	assert.NotEqual(t, previousBlockReward, pow.BlockReward)
}

// Integration Test for Proof of Work process
func TestProofOfWorkProcess(t *testing.T) {
	pow := setupProofOfWork()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	// Create and process transactions
	txs := []*Transaction{
		{
			ID:       "tx1",
			Sender:   "Alice",
			Receiver: "Bob",
			Amount:   big.NewInt(10),
			Fee:      big.NewInt(1),
			Signature: signTransaction(privateKey, "Alice", "Bob", big.NewInt(10), big.NewInt(1)),
		},
		{
			ID:       "tx2",
			Sender:   "Bob",
			Receiver: "Charlie",
			Amount:   big.NewInt(5),
			Fee:      big.NewInt(1),
			Signature: signTransaction(privateKey, "Bob", "Charlie", big.NewInt(5), big.NewInt(1)),
		},
	}

	err = pow.ProcessTransactions(txs)
	assert.NoError(t, err)

	// Mine a block
	block, err := pow.MineBlock()
	assert.NoError(t, err)
	assert.NotEmpty(t, block.Hash)

	// Validate the mined block
	isValid := pow.ValidateBlockHash(block.Hash)
	assert.True(t, isValid)

	// Check if the block was added to the blockchain
	assert.Equal(t, 1, len(pow.Blockchain))
}

func signTransaction(privateKey *ecdsa.PrivateKey, sender, receiver string, amount, fee *big.Int) []byte {
	hasher := sha256.New()
	data := fmt.Sprintf("%s:%s:%d:%d", sender, receiver, amount, fee)
	hasher.Write([]byte(data))
	hash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return signature
}
