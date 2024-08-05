package ai

import (
    "encoding/json"
    "errors"
    "log"
    "math"
    "os"
    "time"

    "github.com/syndtr/goleveldb/leveldb"
    "golang.org/x/crypto/argon2"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID        string    `json:"id"`
    From      string    `json:"from"`
    To        string    `json:"to"`
    Amount    float64   `json:"amount"`
    Timestamp time.Time `json:"timestamp"`
}

// FraudDetectionConfig holds configuration for the fraud detection system
type FraudDetectionConfig struct {
    Sensitivity float64 `json:"sensitivity"`
}

var fraudConfig FraudDetectionConfig

const (
    fraudConfigFile = "fraud_config.json"
    transactionDB   = "transaction_db"
    saltSize        = 16
)

// InitializeFraudDetection initializes the fraud detection system
func InitializeFraudDetection() error {
    // Load the fraud detection configuration
    configFile, err := os.Open(fraudConfigFile)
    if err != nil {
        return err
    }
    defer configFile.Close()
    return json.NewDecoder(configFile).Decode(&fraudConfig)
}

// SaveFraudDetectionConfig saves the fraud detection configuration
func SaveFraudDetectionConfig() error {
    configFile, err := os.Create(fraudConfigFile)
    if err != nil {
        return err
    }
    defer configFile.Close()
    return json.NewEncoder(configFile).Encode(&fraudConfig)
}

// AnalyzeTransaction analyzes a transaction for fraud
func AnalyzeTransaction(tx Transaction) (bool, error) {
    // Open LevelDB database for transactions
    db, err := leveldb.OpenFile(transactionDB, nil)
    if err != nil {
        return false, err
    }
    defer db.Close()

    // Retrieve and analyze historical transactions
    iter := db.NewIterator(nil, nil)
    defer iter.Release()

    var transactions []Transaction
    for iter.Next() {
        var t Transaction
        if err := json.Unmarshal(iter.Value(), &t); err != nil {
            continue
        }
        transactions = append(transactions, t)
    }

    // Compute fraud score based on historical data
    fraudScore := computeFraudScore(tx, transactions)
    return fraudScore > fraudConfig.Sensitivity, nil
}

// computeFraudScore computes a fraud score based on historical transactions
func computeFraudScore(tx Transaction, transactions []Transaction) float64 {
    // Example: Simple outlier detection using standard deviation
    var amounts []float64
    for _, t := range transactions {
        if t.From == tx.From {
            amounts = append(amounts, t.Amount)
        }
    }
    if len(amounts) == 0 {
        return 0
    }

    mean, stdDev := calculateMeanAndStdDev(amounts)
    zScore := (tx.Amount - mean) / stdDev
    return math.Abs(zScore)
}

// calculateMeanAndStdDev calculates the mean and standard deviation of a slice of floats
func calculateMeanAndStdDev(numbers []float64) (mean, stdDev float64) {
    sum := 0.0
    for _, num := range numbers {
        sum += num
    }
    mean = sum / float64(len(numbers))

    variance := 0.0
    for _, num := range numbers {
        variance += math.Pow(num-mean, 2)
    }
    variance /= float64(len(numbers))
    stdDev = math.Sqrt(variance)
    return
}

// RecordTransaction records a transaction in the database
func RecordTransaction(tx Transaction) error {
    db, err := leveldb.OpenFile(transactionDB, nil)
    if err != nil {
        return err
    }
    defer db.Close()

    txData, err := json.Marshal(tx)
    if err != nil {
        return err
    }

    return db.Put([]byte(tx.ID), txData, nil)
}

// HashPassword hashes a password using Argon2
func HashPassword(password string) (string, []byte, error) {
    salt := make([]byte, saltSize)
    if _, err := rand.Read(salt); err != nil {
        return "", nil, err
    }
    hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", hash), salt, nil
}

// VerifyPassword verifies a password against a given hash and salt
func VerifyPassword(password string, hash string, salt []byte) bool {
    newHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", newHash) == hash
}

func main() {
    // Initialize fraud detection system
    if err := InitializeFraudDetection(); err != nil {
        log.Fatalf("failed to initialize fraud detection: %v", err)
    }

    // Example transaction analysis
    tx := Transaction{
        ID:        "tx123",
        From:      "user1",
        To:        "user2",
        Amount:    1000.0,
        Timestamp: time.Now(),
    }

    isFraudulent, err := AnalyzeTransaction(tx)
    if err != nil {
        log.Fatalf("failed to analyze transaction: %v", err)
    }

    if isFraudulent {
        log.Printf("transaction %s is potentially fraudulent", tx.ID)
    } else {
        log.Printf("transaction %s is not fraudulent", tx.ID)
    }

    // Record the transaction
    if err := RecordTransaction(tx); err != nil {
        log.Fatalf("failed to record transaction: %v", err)
    }
}
