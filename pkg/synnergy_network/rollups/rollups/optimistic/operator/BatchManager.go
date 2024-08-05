package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Transaction struct {
	ID        string
	Sender    string
	Recipient string
	Data      []byte
	Timestamp time.Time
	Signature string
}

type Batch struct {
	ID            string
	Transactions  []*Transaction
	CreatedAt     time.Time
	Processed     bool
	ProcessedTime time.Time
	PrevHash      string
	Hash          string
}

type BatchManager struct {
	mu            sync.Mutex
	CurrentBatch  *Batch
	CompletedBatches []*Batch
	MaxBatchSize  int
	BatchInterval time.Duration
}

func NewBatchManager(maxBatchSize int, batchInterval time.Duration) *BatchManager {
	return &BatchManager{
		MaxBatchSize:     maxBatchSize,
		BatchInterval:    batchInterval,
		CurrentBatch:     nil,
		CompletedBatches: []*Batch{},
	}
}

func (bm *BatchManager) StartBatch() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.CurrentBatch != nil {
		fmt.Println("A batch is already in progress.")
		return
	}

	batchID := generateBatchID()
	bm.CurrentBatch = &Batch{
		ID:           batchID,
		Transactions: []*Transaction{},
		CreatedAt:    time.Now(),
		Processed:    false,
	}

	fmt.Printf("New batch started with ID: %s\n", bm.CurrentBatch.ID)
}

func (bm *BatchManager) AddTransaction(tx *Transaction) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.CurrentBatch == nil {
		return errors.New("no batch in progress")
	}

	if len(bm.CurrentBatch.Transactions) >= bm.MaxBatchSize {
		return errors.New("current batch is full")
	}

	bm.CurrentBatch.Transactions = append(bm.CurrentBatch.Transactions, tx)
	fmt.Printf("Transaction %s added to batch %s\n", tx.ID, bm.CurrentBatch.ID)

	if len(bm.CurrentBatch.Transactions) == bm.MaxBatchSize {
		go bm.ProcessBatch()
	}

	return nil
}

func (bm *BatchManager) ProcessBatch() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.CurrentBatch == nil {
		fmt.Println("No batch to process.")
		return
	}

	if bm.CurrentBatch.Processed {
		fmt.Println("Current batch already processed.")
		return
	}

	prevHash := ""
	if len(bm.CompletedBatches) > 0 {
		prevHash = bm.CompletedBatches[len(bm.CompletedBatches)-1].Hash
	}

	bm.CurrentBatch.Hash = calculateHash(bm.CurrentBatch, prevHash)
	bm.CurrentBatch.Processed = true
	bm.CurrentBatch.ProcessedTime = time.Now()

	bm.CompletedBatches = append(bm.CompletedBatches, bm.CurrentBatch)
	fmt.Printf("Batch %s processed and completed.\n", bm.CurrentBatch.ID)

	bm.CurrentBatch = nil
	go bm.StartBatch()
}

func (bm *BatchManager) SyncWithNode(nodeID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	fmt.Printf("Synchronizing batches with node %s\n", nodeID)
	// Implement synchronization logic with the specified node
}

func generateBatchID() string {
	timestamp := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	return hex.EncodeToString(hash[:])
}

func calculateHash(batch *Batch, prevHash string) string {
	record := batch.ID + batch.CreatedAt.String() + prevHash
	for _, tx := range batch.Transactions {
		record += tx.ID + tx.Sender + tx.Recipient + string(tx.Data) + tx.Timestamp.String()
	}

	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// EncryptTransaction encrypts transaction data using Argon2/AES.
func EncryptTransaction(tx *Transaction, key string) (string, error) {
	// Encryption logic using Argon2 and AES goes here
	return "", nil
}

// DecryptTransaction decrypts transaction data using Argon2/AES.
func DecryptTransaction(encryptedData, key string) (*Transaction, error) {
	// Decryption logic using Argon2 and AES goes here
	return nil, nil
}

// VerifyTransactionSignature verifies the signature of a transaction.
func VerifyTransactionSignature(tx *Transaction, publicKey string) bool {
	// Verification logic goes here
	return true
}
