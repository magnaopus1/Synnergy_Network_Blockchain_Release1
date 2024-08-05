package storage

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/blockchain/chain"
	"github.com/synnergy_network/pkg/blockchain/crypto"
	"github.com/synnergy_network/pkg/compliance/transaction_monitoring"
	"github.com/synnergy_network/pkg/consensus/proof_of_work"
	"github.com/synnergy_network/pkg/cryptography/encryption"
	"github.com/synnergy_network/pkg/identity_services/identity_verification"
	"github.com/synnergy_network/pkg/wallet/utils"
)

// BalanceService manages the balance of wallets within the blockchain network.
type BalanceService struct {
	blockchainService *chain.BlockchainService
	balances          sync.Map // map[string]float64
}

// NewBalanceService initializes and returns a new BalanceService.
func NewBalanceService(blockchainService *chain.BlockchainService) *BalanceService {
	return &BalanceService{
		blockchainService: blockchainService,
	}
}

// GetBalance returns the balance of a wallet.
func (bs *BalanceService) GetBalance(walletAddress string) (float64, error) {
	if balance, ok := bs.balances.Load(walletAddress); ok {
		return balance.(float64), nil
	}
	return 0, errors.New("wallet address not found")
}

// UpdateBalance updates the balance of a wallet based on transactions.
func (bs *BalanceService) UpdateBalance(walletAddress string, amount float64, add bool) error {
	currentBalance, err := bs.GetBalance(walletAddress)
	if err != nil {
		return err
	}
	if add {
		bs.balances.Store(walletAddress, currentBalance+amount)
	} else {
		bs.balances.Store(walletAddress, currentBalance-amount)
	}
	return nil
}

// CalculateBalances calculates balances for all wallets based on the blockchain.
func (bs *BalanceService) CalculateBalances() {
	transactions := bs.blockchainService.GetTransactions()
	for _, tx := range transactions {
		bs.UpdateBalance(tx.From, tx.Amount, false)
		bs.UpdateBalance(tx.To, tx.Amount, true)
	}
}

// MonitorBalanceChanges provides real-time notifications for balance changes.
func (bs *BalanceService) MonitorBalanceChanges(walletAddress string, callback func(balance float64)) {
	go func() {
		previousBalance, _ := bs.GetBalance(walletAddress)
		for {
			currentBalance, _ := bs.GetBalance(walletAddress)
			if currentBalance != previousBalance {
				callback(currentBalance)
				previousBalance = currentBalance
			}
			time.Sleep(10 * time.Second) // Check for balance changes every 10 seconds
		}
	}()
}

// AddressAliasService provides alias management for wallet addresses.
type AddressAliasService struct {
	aliases sync.Map // map[string]string
}

// NewAddressAliasService initializes and returns a new AddressAliasService.
func NewAddressAliasService() *AddressAliasService {
	return &AddressAliasService{}
}

// AssignAlias assigns a human-readable alias to a wallet address.
func (aas *AddressAliasService) AssignAlias(walletAddress, alias string) error {
	if _, exists := aas.aliases.Load(alias); exists {
		return errors.New("alias already in use")
	}
	aas.aliases.Store(alias, walletAddress)
	return nil
}

// ResolveAlias resolves an alias to its corresponding wallet address.
func (aas *AddressAliasService) ResolveAlias(alias string) (string, error) {
	if address, ok := aas.aliases.Load(alias); ok {
		return address.(string), nil
	}
	return "", errors.New("alias not found")
}

// DynamicFeeAdjustmentService manages dynamic fee adjustments based on network conditions.
type DynamicFeeAdjustmentService struct {
	blockchainService *chain.BlockchainService
	baseFee           float64
	feeMultiplier     float64
}

// NewDynamicFeeAdjustmentService initializes and returns a new DynamicFeeAdjustmentService.
func NewDynamicFeeAdjustmentService(blockchainService *chain.BlockchainService, baseFee, feeMultiplier float64) *DynamicFeeAdjustmentService {
	return &DynamicFeeAdjustmentService{
		blockchainService: blockchainService,
		baseFee:           baseFee,
		feeMultiplier:     feeMultiplier,
	}
}

// AdjustFee dynamically adjusts transaction fees based on network congestion.
func (dfas *DynamicFeeAdjustmentService) AdjustFee() float64 {
	congestionLevel := dfas.blockchainService.GetNetworkCongestionLevel()
	return dfas.baseFee + (dfas.baseFee * dfas.feeMultiplier * congestionLevel)
}

// PrivacyPreservingBalanceService provides privacy-preserving balance management.
type PrivacyPreservingBalanceService struct {
	balanceService *BalanceService
}

// NewPrivacyPreservingBalanceService initializes and returns a new PrivacyPreservingBalanceService.
func NewPrivacyPreservingBalanceService(balanceService *BalanceService) *PrivacyPreservingBalanceService {
	return &PrivacyPreservingBalanceService{
		balanceService: balanceService,
	}
}

// GetPrivateBalance returns the balance of a wallet using zero-knowledge proofs.
func (ppbs *PrivacyPreservingBalanceService) GetPrivateBalance(walletAddress string) (string, error) {
	balance, err := ppbs.balanceService.GetBalance(walletAddress)
	if err != nil {
		return "", err
	}
	// Implement zero-knowledge proof for balance here (mocked for demonstration)
	privateBalance := ppbs.zeroKnowledgeProof(balance)
	return privateBalance, nil
}

// zeroKnowledgeProof is a mock function for demonstrating zero-knowledge proof.
func (ppbs *PrivacyPreservingBalanceService) zeroKnowledgeProof(balance float64) string {
	proof := map[string]interface{}{
		"balance": balance,
		"proof":   "zkp_mock_proof",
	}
	proofJSON, _ := json.Marshal(proof)
	return string(proofJSON)
}

// BlockchainService provides methods to interact with the blockchain
type BlockchainService struct {
	transactions []chain.Transaction
	mu           sync.Mutex
}

// NewBlockchainService initializes and returns a new BlockchainService
func NewBlockchainService() *BlockchainService {
	return &BlockchainService{}
}

// GetTransactions returns the list of transactions in the blockchain
func (bs *BlockchainService) GetTransactions() []chain.Transaction {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.transactions
}

// AddTransaction adds a new transaction to the blockchain
func (bs *BlockchainService) AddTransaction(tx chain.Transaction) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.transactions = append(bs.transactions, tx)
}

// GetNetworkCongestionLevel returns the current network congestion level (mock implementation)
func (bs *BlockchainService) GetNetworkCongestionLevel() float64 {
	// Mock implementation: Return a random congestion level between 0 and 1
	return float64(len(bs.transactions)%10) / 10
}

// Implementing more methods based on the whitepaper description

// VerifyTransaction verifies a transaction based on double-spending prevention
func (bs *BlockchainService) VerifyTransaction(tx chain.Transaction) error {
	for _, existingTx := range bs.transactions {
		if existingTx.From == tx.From && existingTx.Time.Before(tx.Time) {
			return errors.New("double-spending detected")
		}
	}
	return nil
}

// AddTransactionWithVerification adds a new transaction to the blockchain with verification
func (bs *BlockchainService) AddTransactionWithVerification(tx chain.Transaction) error {
	if err := bs.VerifyTransaction(tx); err != nil {
		return err
	}
	bs.AddTransaction(tx)
	return nil
}

// DetailedTransaction represents a detailed transaction structure
type DetailedTransaction struct {
	chain.Transaction
	BlockNumber uint64
}

// GetTransactionHistory returns the transaction history for a wallet
func (bs *BlockchainService) GetTransactionHistory(walletAddress string) ([]DetailedTransaction, error) {
	var history []DetailedTransaction
	for _, tx := range bs.transactions {
		if tx.From == walletAddress || tx.To == walletAddress {
			history = append(history, DetailedTransaction{Transaction: tx, BlockNumber: uint64(len(bs.transactions))})
		}
	}
	return history, nil
}

// Implementing additional features based on whitepaper description

// DetailedBalanceCalculation performs a detailed balance calculation considering transaction fees and rewards
func (bs *BalanceService) DetailedBalanceCalculation(walletAddress string) (float64, error) {
	balance, err := bs.GetBalance(walletAddress)
	if err != nil {
		return 0, err
	}

	// Example of deducting transaction fees and adding rewards
	transactions := bs.blockchainService.GetTransactions()
	for _, tx := range transactions {
		if tx.From == walletAddress {
			balance -= tx.Amount * 0.01 // Deduct 1% as transaction fee (example)
		}
		if tx.To == walletAddress {
			balance += tx.Amount * 0.01 // Add 1% as reward (example)
		}
	}

	return balance, nil
}

// Implementing a monitoring service for suspicious activity
type SuspiciousActivityMonitoringService struct {
	balanceService *BalanceService
	alerts         chan string
}

// NewSuspiciousActivityMonitoringService initializes and returns a new SuspiciousActivityMonitoringService
func NewSuspiciousActivityMonitoringService(balanceService *BalanceService) *SuspiciousActivityMonitoringService {
	return &SuspiciousActivityMonitoringService{
		balanceService: balanceService,
		alerts:         make(chan string, 100),
	}
}

// MonitorSuspiciousActivity monitors and logs suspicious activity on wallets
func (sams *SuspiciousActivityMonitoringService) MonitorSuspiciousActivity(walletAddress string) {
	go func() {
		previousBalance, _ := sams.balanceService.GetBalance(walletAddress)
		for {
			currentBalance, _ := sams.balanceService.GetBalance(walletAddress)
			if currentBalance < previousBalance*0.5 { // Example threshold for suspicious activity
				alertMsg := sams.generateAlertMessage(walletAddress, "Suspicious activity detected: balance dropped by more than 50%")
				sams.alerts <- alertMsg
			}
			previousBalance = currentBalance
			time.Sleep(10 * time.Second) // Check for balance changes every 10 seconds
		}
	}()
}

// generateAlertMessage generates an alert message for suspicious activity
func (sams *SuspiciousActivityMonitoringService) generateAlertMessage(walletAddress, message string) string {
	alert := map[string]interface{}{
		"wallet":   walletAddress,
		"message":  message,
		"time":     time.Now(),
		"alertType": "SuspiciousActivity",
	}
	alertMsg, _ := json.Marshal(alert)
	return string(alertMsg)
}

// GetAlerts returns a channel to listen for suspicious activity alerts
func (sams *SuspiciousActivityMonitoringService) GetAlerts() <-chan string {
	return sams.alerts
}
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
	"github.com/synnergy_network/pkg/consensus/proof_of_history"
	"github.com/synnergy_network/pkg/cryptography/encryption"
	"github.com/synnergy_network/pkg/cryptography/hash"
	"github.com/synnergy_network/pkg/compliance/audit_trails"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// SecureStorageService provides methods for securely storing and retrieving sensitive data.
type SecureStorageService struct {
	storage sync.Map // map[string]string for encrypted data storage
}

// NewSecureStorageService initializes and returns a new SecureStorageService.
func NewSecureStorageService() *SecureStorageService {
	return &SecureStorageService{}
}

// Store securely stores data with a given key and passphrase.
func (sss *SecureStorageService) Store(key, data, passphrase string) error {
	encryptedData, err := sss.encrypt([]byte(data), passphrase)
	if err != nil {
		return err
	}
	sss.storage.Store(key, encryptedData)
	sss.logAuditTrail(key, "store")
	return nil
}

// Retrieve retrieves and decrypts data for a given key and passphrase.
func (sss *SecureStorageService) Retrieve(key, passphrase string) (string, error) {
	encryptedData, ok := sss.storage.Load(key)
	if !ok {
		return "", errors.New("data not found")
	}
	decryptedData, err := sss.decrypt(encryptedData.(string), passphrase)
	if err != nil {
		return "", err
	}
	sss.logAuditTrail(key, "retrieve")
	return string(decryptedData), nil
}

// encrypt encrypts data using AES with a provided passphrase.
func (sss *SecureStorageService) encrypt(data []byte, passphrase string) (string, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES with a provided passphrase.
func (sss *SecureStorageService) decrypt(encrypted string, passphrase string) ([]byte, error) {
	key := sha256.Sum256([]byte(passphrase))
	ciphertext, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// GenerateArgon2Key generates a key using Argon2 key derivation function.
func (sss *SecureStorageService) GenerateArgon2Key(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32), nil
}

// GenerateScryptKey generates a key using Scrypt key derivation function.
func (sss *SecureStorageService) GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// SecureDataWithArgon2 securely stores data using Argon2 for key derivation.
func (sss *SecureStorageService) SecureDataWithArgon2(key, data, password string, salt []byte) error {
	derivedKey, err := sss.GenerateArgon2Key([]byte(password), salt)
	if err != nil {
		return err
	}
	return sss.Store(key, data, string(derivedKey))
}

// SecureDataWithScrypt securely stores data using Scrypt for key derivation.
func (sss *SecureStorageService) SecureDataWithScrypt(key, data, password string, salt []byte) error {
	derivedKey, err := sss.GenerateScryptKey([]byte(password), salt)
	if err != nil {
		return err
	}
	return sss.Store(key, data, string(derivedKey))
}

// RetrieveDataWithArgon2 retrieves and decrypts data using Argon2 for key derivation.
func (sss *SecureStorageService) RetrieveDataWithArgon2(key, password string, salt []byte) (string, error) {
	derivedKey, err := sss.GenerateArgon2Key([]byte(password), salt)
	if err != nil {
		return "", err
	}
	return sss.Retrieve(key, string(derivedKey))
}

// RetrieveDataWithScrypt retrieves and decrypts data using Scrypt for key derivation.
func (sss *SecureStorageService) RetrieveDataWithScrypt(key, password string, salt []byte) (string, error) {
	derivedKey, err := sss.GenerateScryptKey([]byte(password), salt)
	if err != nil {
		return "", err
	}
	return sss.Retrieve(key, string(derivedKey))
}

// logAuditTrail logs actions taken on data for compliance and auditing purposes.
func (sss *SecureStorageService) logAuditTrail(key, action string) {
	audit := audit_trails.NewAuditTrail("secure_storage", key, action)
	audit.Record()
}

package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
	"github.com/synnergy_network/pkg/storage/decentralized_storage"
	"github.com/synnergy_network/pkg/storage/encryption"
	"github.com/synnergy_network/pkg/compliance/audit_trails"
	"github.com/synnergy_network/pkg/compliance/data_protection"
)

// WalletStorageCleanupService provides methods to manage storage cleanup for wallets
type WalletStorageCleanupService struct {
	blockchainService   *blockchain.BlockchainService
	walletService       *wallet.WalletService
	decentralizedStorage *decentralized_storage.DecentralizedStorageService
	encryptionService   *encryption.EncryptionService
	auditService        *audit_trails.AuditTrailService
	dataProtectionService *data_protection.DataProtectionService
	mutex               sync.Mutex
	cleanupInterval     time.Duration
	alerts              chan string
}

// NewWalletStorageCleanupService initializes and returns a new WalletStorageCleanupService
func NewWalletStorageCleanupService(
	blockchainService *blockchain.BlockchainService,
	walletService *wallet.WalletService,
	decentralizedStorage *decentralized_storage.DecentralizedStorageService,
	encryptionService *encryption.EncryptionService,
	auditService *audit_trails.AuditTrailService,
	dataProtectionService *data_protection.DataProtectionService,
	cleanupInterval time.Duration) *WalletStorageCleanupService {
	return &WalletStorageCleanupService{
		blockchainService:     blockchainService,
		walletService:         walletService,
		decentralizedStorage:  decentralizedStorage,
		encryptionService:     encryptionService,
		auditService:          auditService,
		dataProtectionService: dataProtectionService,
		cleanupInterval:       cleanupInterval,
		alerts:                make(chan string, 100),
	}
}

// StartCleanupRoutine starts the routine to clean up old storage files periodically
func (ws *WalletStorageCleanupService) StartCleanupRoutine() {
	ticker := time.NewTicker(ws.cleanupInterval)
	go func() {
		for range ticker.C {
			ws.CleanupStorage()
		}
	}()
}

// CleanupStorage performs the cleanup of old or unnecessary storage files
func (ws *WalletStorageCleanupService) CleanupStorage() {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()

	// Fetch the list of storage files to be cleaned up
	files, err := ws.decentralizedStorage.ListFiles()
	if err != nil {
		log.Printf("Error listing files: %v", err)
		return
	}

	for _, file := range files {
		// Check if the file needs to be cleaned up
		if ws.needsCleanup(file) {
			err := ws.deleteFile(file)
			if err != nil {
				log.Printf("Error deleting file %s: %v", file, err)
			} else {
				ws.auditService.RecordEvent("FileCleanup", file)
			}
		}
	}
}

// needsCleanup determines if a file needs to be cleaned up based on its age and other criteria
func (ws *WalletStorageCleanupService) needsCleanup(file string) bool {
	info, err := os.Stat(file)
	if err != nil {
		log.Printf("Error getting file info for %s: %v", file, err)
		return false
	}

	// Example cleanup criteria: files older than 30 days
	return time.Since(info.ModTime()) > 30*24*time.Hour
}

// deleteFile securely deletes a file from storage
func (ws *WalletStorageCleanupService) deleteFile(file string) error {
	// Ensure file is securely erased
	err := ws.secureErase(file)
	if err != nil {
		return err
	}

	return os.Remove(file)
}

// secureErase ensures that a file's contents are securely erased
func (ws *WalletStorageCleanupService) secureErase(file string) error {
	// Open the file
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// Overwrite the file with random data
	info, err := f.Stat()
	if err != nil {
		return err
	}

	size := info.Size()
	randomData := make([]byte, size)
	_, err = rand.Read(randomData)
	if err != nil {
		return err
	}

	_, err = f.WriteAt(randomData, 0)
	return err
}

// GetAlerts returns a channel to listen for cleanup alerts
func (ws *WalletStorageCleanupService) GetAlerts() <-chan string {
	return ws.alerts
}

// AuditTrail logs the actions taken for compliance and auditing purposes
func (ws *WalletStorageCleanupService) AuditTrail(action, file string) {
	logData := map[string]interface{}{
		"action":   action,
		"file":     file,
		"time":     time.Now(),
		"alertType": "StorageCleanup",
	}
	logMsg, _ := json.Marshal(logData)
	log.Println(string(logMsg))
	ws.auditService.RecordEvent("StorageCleanup", logMsg)
}

// Example usage of encryption for sensitive data before storage
func (ws *WalletStorageCleanupService) encryptData(data []byte, passphrase string) ([]byte, error) {
	return ws.encryptionService.Encrypt(data, passphrase)
}

// Example usage of decryption for sensitive data after retrieval
func (ws *WalletStorageCleanupService) decryptData(data []byte, passphrase string) ([]byte, error) {
	return ws.encryptionService.Decrypt(data, passphrase)
}
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/synnergy_network/pkg/blockchain/chain"
	"github.com/synnergy_network/pkg/blockchain/crypto"
	"github.com/synnergy_network/pkg/compliance/transaction_monitoring"
	"github.com/synnergy_network/pkg/cryptography/encryption"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID             string  `json:"id"`
	From           string  `json:"from"`
	To             string  `json:"to"`
	Amount         float64 `json:"amount"`
	Timestamp      int64   `json:"timestamp"`
	Signature      string  `json:"signature"`
	TransactionFee float64 `json:"transaction_fee"`
	Hash           string  `json:"hash"`
}

// TransactionStorage manages the storage of transactions
type TransactionStorage struct {
	transactions map[string]Transaction
	mu           sync.RWMutex
	filePath     string
}

// NewTransactionStorage initializes and returns a new TransactionStorage
func NewTransactionStorage(filePath string) *TransactionStorage {
	ts := &TransactionStorage{
		transactions: make(map[string]Transaction),
		filePath:     filePath,
	}
	ts.loadFromFile()
	return ts
}

// AddTransaction adds a new transaction to the storage
func (ts *TransactionStorage) AddTransaction(from, to string, amount, transactionFee float64, timestamp int64, signature string) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := uuid.New().String()
	hash := ts.calculateHash(from, to, amount, transactionFee, timestamp, signature)
	transaction := Transaction{
		ID:             id,
		From:           from,
		To:             to,
		Amount:         amount,
		Timestamp:      timestamp,
		Signature:      signature,
		TransactionFee: transactionFee,
		Hash:           hash,
	}
	ts.transactions[id] = transaction
	err := ts.saveToFile()
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetTransaction retrieves a transaction by ID
func (ts *TransactionStorage) GetTransaction(id string) (Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	transaction, exists := ts.transactions[id]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}
	return transaction, nil
}

// GetTransactionsByAddress retrieves all transactions associated with a given address
func (ts *TransactionStorage) GetTransactionsByAddress(address string) ([]Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var transactions []Transaction
	for _, transaction := range ts.transactions {
		if transaction.From == address || transaction.To == address {
			transactions = append(transactions, transaction)
		}
	}
	return transactions, nil
}

// GetAllTransactions retrieves all transactions
func (ts *TransactionStorage) GetAllTransactions() ([]Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var transactions []Transaction
	for _, transaction := range ts.transactions {
		transactions = append(transactions, transaction)
	}
	return transactions, nil
}

// DeleteTransaction deletes a transaction by ID
func (ts *TransactionStorage) DeleteTransaction(id string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.transactions[id]; !exists {
		return errors.New("transaction not found")
	}
	delete(ts.transactions, id)
	return ts.saveToFile()
}

// saveToFile saves the current state of transactions to a file
func (ts *TransactionStorage) saveToFile() error {
	data, err := json.Marshal(ts.transactions)
	if err != nil {
		return err
	}
	return os.WriteFile(ts.filePath, data, 0644)
}

// loadFromFile loads the transactions from a file
func (ts *TransactionStorage) loadFromFile() error {
	file, err := os.ReadFile(ts.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // File does not exist, no transactions to load
		}
		return err
	}
	return json.Unmarshal(file, &ts.transactions)
}

// validateTransaction validates the integrity of a transaction
func (ts *TransactionStorage) validateTransaction(tx Transaction) bool {
	expectedHash := ts.calculateHash(tx.From, tx.To, tx.Amount, tx.TransactionFee, tx.Timestamp, tx.Signature)
	return expectedHash == tx.Hash
}

// calculateHash calculates the hash of a transaction
func (ts *TransactionStorage) calculateHash(from, to string, amount, transactionFee float64, timestamp int64, signature string) string {
	data := from + to + string(amount) + string(transactionFee) + string(timestamp) + signature
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// MonitorSuspiciousTransactions monitors transactions for suspicious activity
func (ts *TransactionStorage) MonitorSuspiciousTransactions(callback func(transaction Transaction)) {
	go func() {
		for {
			ts.mu.RLock()
			for _, transaction := range ts.transactions {
				if ts.isSuspicious(transaction) {
					callback(transaction)
				}
			}
			ts.mu.RUnlock()
			time.Sleep(10 * time.Second) // Check for suspicious transactions every 10 seconds
		}
	}()
}

// isSuspicious checks if a transaction is suspicious based on custom criteria
func (ts *TransactionStorage) isSuspicious(tx Transaction) bool {
	// Implement your custom logic to identify suspicious transactions
	// Example: Transactions with very high amounts could be flagged as suspicious
	return tx.Amount > 10000
}

