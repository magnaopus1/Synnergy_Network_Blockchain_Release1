package analytics

import (
	"encoding/json"
	"log"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// TransactionRecord stores individual transaction data
type TransactionRecord struct {
	Timestamp    time.Time
	TransactionID string
	FromAddress  string
	ToAddress    string
	Value        float64
	IsSuspicious bool
}

// PatternAnalysis holds results from transaction pattern analysis
type PatternAnalysis struct {
	SuspiciousTransactions []TransactionRecord
	NormalTransactions     []TransactionRecord
}

// TransactionPatterns encapsulates the logic for transaction pattern analysis
type TransactionPatterns struct {
	transactions []TransactionRecord
	analysis     PatternAnalysis
}

// Constants for encryption
const (
	Salt      = "secure-salt-here"
	KeyLength = 32
)

// NewTransactionPatterns initializes a TransactionPatterns instance
func NewTransactionPatterns() *TransactionPatterns {
	return &TransactionPatterns{}
}

// AddTransaction adds a new transaction to the analysis pool
func (tp *TransactionPatterns) AddTransaction(tx TransactionRecord) {
	tp.transactions = append(tp.transactions, tx)
	log.Printf("Transaction added: %v", tx)
}

// AnalyzePatterns analyzes the transactions to identify patterns
func (tp *TransactionPatterns) AnalyzePatterns() {
	for _, tx := range tp.transactions {
		if tp.isSuspicious(tx) {
			tp.analysis.SuspiciousTransactions = append(tp.analysis.SuspiciousTransactions, tx)
		} else {
			tp.analysis.NormalTransactions = append(tp.analysis.NormalTransactions, tx)
		}
	}
	log.Println("Completed analysis of transaction patterns")
}

// isSuspicious defines the logic to determine if a transaction is suspicious
func (tp *TransactionPatterns) isSuspicious(tx TransactionRecord) bool {
	// Example suspicious criteria: large transactions from new addresses
	return tx.Value > 10000 && tx.FromAddress[:5] == "NEW01"
}

// EncryptAnalysisData securely encrypts analysis results using Argon2
func (tp *TransactionPatterns) EncryptAnalysisData(useArgon bool) ([]byte, error) {
	data, err := json.Marshal(tp.analysis)
	if err != nil {
		log.Printf("Error marshaling analysis data: %v", err)
		return nil, err
	}

	var encryptedData []byte
	if useArgon {
		encryptedData = argon2.IDKey(data, []byte(Salt), 1, 64*1024, 4, KeyLength)
	} else {
		encryptedData, err = scrypt.Key(data, []byte(Salt), 16384, 8, 1, KeyLength)
		if err != nil {
			log.Printf("Error encrypting analysis data: %v", err)
			return nil, err
		}
	}

	return encryptedData, nil
}

// main function to demonstrate usage
func main() {
	tp := NewTransactionPatterns()
	tp.AddTransaction(TransactionRecord{time.Now(), "tx1001", "NEW010001", "address123", 15000, false})
	tp.AddTransaction(TransactionRecord{time.Now(), "tx1002", "address456", "address789", 50, false})

	tp.AnalyzePatterns()

	encryptedData, err := tp.EncryptAnalysisData(true)
	if err != nil {
		log.Fatalf("Failed to encrypt transaction analysis data: %v", err)
	}

	log.Printf("Encrypted Analysis Data: %x", encryptedData)
}
