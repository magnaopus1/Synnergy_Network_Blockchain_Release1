package transaction_monitoring

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Timestamp time.Time `json:"timestamp"`
	Amount    float64   `json:"amount"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Category  string    `json:"category"`
}

// TransactionClassifier classifies transactions based on predefined rules
type TransactionClassifier struct {
	db           *sql.DB
	classifyFunc func(Transaction) string
}

// NewTransactionClassifier initializes a new transaction classifier
func NewTransactionClassifier(db *sql.DB, classifyFunc func(Transaction) string) *TransactionClassifier {
	return &TransactionClassifier{
		db:           db,
		classifyFunc: classifyFunc,
	}
}

// Start begins the transaction classification process
func (tc *TransactionClassifier) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.classifyRecentTransactions()
		case <-ctx.Done():
			return
		}
	}
}

// classifyRecentTransactions fetches recent transactions and classifies them
func (tc *TransactionClassifier) classifyRecentTransactions() {
	transactions, err := tc.fetchRecentTransactions()
	if err != nil {
		log.Println("Error fetching transactions:", err)
		return
	}

	for _, tx := range transactions {
		tx.Category = tc.classifyFunc(tx)
		if err := tc.updateTransactionCategory(tx); err != nil {
			log.Println("Error updating transaction category:", err)
		}
	}
}

// fetchRecentTransactions retrieves recent transactions from the database
func (tc *TransactionClassifier) fetchRecentTransactions() ([]Transaction, error) {
	rows, err := tc.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE timestamp > NOW() - INTERVAL '1 MINUTE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// updateTransactionCategory updates the category of a transaction in the database
func (tc *TransactionClassifier) updateTransactionCategory(tx Transaction) error {
	_, err := tc.db.Exec(`
		UPDATE transactions 
		SET category = $1 
		WHERE id = $2`,
		tx.Category, tx.ID)
	return err
}

// Example classifyFunc that classifies transactions based on predefined rules
func classifyTransaction(tx Transaction) string {
	// Example classification logic (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 {
		return "Large Transaction"
	}
	if tx.Type == "withdrawal" {
		return "Withdrawal"
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return "Normal"
}

// Utility functions for secure communication, encryption, and decryption
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func encrypt(data, passphrase []byte) ([]byte, error) {
	// Use AES for encryption
	block, err := aes.NewCipher(hashPassword(string(passphrase), nil))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(encryptedData, passphrase []byte) ([]byte, error) {
	// Use AES for decryption
	block, err := aes.NewCipher(hashPassword(string(passphrase), nil))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Ensure secure communication between services
func secureCommunication() {
	// Implement secure communication logic here
}
