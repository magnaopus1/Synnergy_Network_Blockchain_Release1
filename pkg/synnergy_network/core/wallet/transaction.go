package transaction

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/compliance"
	"github.com/synnergy_network/pkg/layer0/core/consensus"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
	"github.com/synnergy_network/pkg/layer0/core/wallet/security"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// TransactionReversalService handles the application and processing of transaction reversals
type TransactionReversalService struct {
	blockchainService     *blockchain.BlockchainService
	walletService         *wallet.WalletService
	complianceService     *compliance.ComplianceService
	consensusService      *consensus.ConsensusService
	securityService       *security.SecurityService
	reversalRequests      sync.Map // map[string]TransactionReversalRequest
	alerts                chan string
}

// NewTransactionReversalService initializes and returns a new TransactionReversalService
func NewTransactionReversalService(
	blockchainService *blockchain.BlockchainService,
	walletService *wallet.WalletService,
	complianceService *compliance.ComplianceService,
	consensusService *consensus.ConsensusService,
	securityService *security.SecurityService,
) *TransactionReversalService {
	return &TransactionReversalService{
		blockchainService: blockchainService,
		walletService:     walletService,
		complianceService: complianceService,
		consensusService:  consensusService,
		securityService:   securityService,
		alerts:            make(chan string, 100),
	}
}

// TransactionReversalRequest represents a request to reverse a transaction
type TransactionReversalRequest struct {
	ID            string `json:"id"`
	TransactionID string `json:"transaction_id"`
	Requester     string `json:"requester"`
	Reason        string `json:"reason"`
	Status        string `json:"status"`
	Timestamp     int64  `json:"timestamp"`
}

// ApplyForTransactionReversal allows users to apply for a transaction reversal
func (trs *TransactionReversalService) ApplyForTransactionReversal(transactionID, requester, reason string) (string, error) {
	if trs.securityService.IsWalletFrozen(requester) {
		return "", errors.New("wallet is frozen, cannot apply for transaction reversal")
	}

	id := generateID()
	request := TransactionReversalRequest{
		ID:            id,
		TransactionID: transactionID,
		Requester:     requester,
		Reason:        reason,
		Status:        "pending",
		Timestamp:     time.Now().Unix(),
	}

	trs.reversalRequests.Store(id, request)
	trs.alerts <- trs.generateAlertMessage(requester, fmt.Sprintf("Transaction reversal requested for %s", transactionID))
	return id, nil
}

// ProcessReversalRequest processes a pending transaction reversal request
func (trs *TransactionReversalService) ProcessReversalRequest(requestID string) error {
	value, ok := trs.reversalRequests.Load(requestID)
	if !ok {
		return errors.New("reversal request not found")
	}

	request := value.(TransactionReversalRequest)
	if request.Status != "pending" {
		return errors.New("reversal request is not in a pending state")
	}

	transaction, err := trs.blockchainService.GetTransaction(request.TransactionID)
	if err != nil {
		return err
	}

	if err := trs.complianceService.ValidateReversal(request.Requester, request.TransactionID); err != nil {
		return err
	}

	if err := trs.consensusService.ApproveReversal(request.TransactionID); err != nil {
		return err
	}

	trs.blockchainService.ReverseTransaction(transaction)
	request.Status = "approved"
	trs.reversalRequests.Store(requestID, request)
	trs.alerts <- trs.generateAlertMessage(request.Requester, fmt.Sprintf("Transaction reversal approved for %s", request.TransactionID))
	return nil
}

// RejectReversalRequest rejects a pending transaction reversal request
func (trs *TransactionReversalService) RejectReversalRequest(requestID string, reason string) error {
	value, ok := trs.reversalRequests.Load(requestID)
	if !ok {
		return errors.New("reversal request not found")
	}

	request := value.(TransactionReversalRequest)
	if request.Status != "pending" {
		return errors.New("reversal request is not in a pending state")
	}

	request.Status = "rejected"
	request.Reason = reason
	trs.reversalRequests.Store(requestID, request)
	trs.alerts <- trs.generateAlertMessage(request.Requester, fmt.Sprintf("Transaction reversal rejected for %s", request.TransactionID))
	return nil
}

// ListReversalRequests lists all transaction reversal requests
func (trs *TransactionReversalService) ListReversalRequests() ([]TransactionReversalRequest, error) {
	var requests []TransactionReversalRequest
	trs.reversalRequests.Range(func(key, value interface{}) bool {
		requests = append(requests, value.(TransactionReversalRequest))
		return true
	})
	return requests, nil
}

// GetReversalRequest retrieves a transaction reversal request by ID
func (trs *TransactionReversalService) GetReversalRequest(id string) (TransactionReversalRequest, error) {
	value, ok := trs.reversalRequests.Load(id)
	if !ok {
		return TransactionReversalRequest{}, errors.New("reversal request not found")
	}
	return value.(TransactionReversalRequest), nil
}

// generateAlertMessage generates an alert message for transaction reversal actions
func (trs *TransactionReversalService) generateAlertMessage(requester, action string) string {
	alert := map[string]interface{}{
		"message":   action,
		"requester": requester,
		"time":      time.Now(),
		"alertType": "TransactionReversal",
	}
	alertMsg, _ := json.Marshal(alert)
	return string(alertMsg)
}

// GetAlerts returns a channel to listen for transaction reversal alerts
func (trs *TransactionReversalService) GetAlerts() <-chan string {
	return trs.alerts
}

// generateID generates a unique identifier for transaction reversal requests
func generateID() string {
	return hex.EncodeToString(generateRandomBytes(16))
}

// generateRandomBytes generates random bytes of specified length
func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return bytes
}

package transaction

import (
    "errors"
    "sync"
    "time"

    "github.com/synnergy_network/pkg/blockchain/chain"
    "github.com/synnergy_network/pkg/blockchain/crypto"
    "github.com/synnergy_network/pkg/blockchain/utils"
    "github.com/synnergy_network/pkg/consensus/proof_of_stake"
    "github.com/synnergy_network/pkg/consensus/proof_of_work"
    "github.com/synnergy_network/pkg/consensus/proof_of_history"
    "github.com/synnergy_network/pkg/consensus/synthron_coin"
    "github.com/synnergy_network/pkg/compliance/audit_trails"
    "github.com/synnergy_network/pkg/compliance/transaction_monitoring"
    "github.com/synnergy_network/pkg/cryptography/encryption"
    "github.com/synnergy_network/pkg/cryptography/hash"
    "github.com/synnergy_network/pkg/cryptography/keys"
    "github.com/synnergy_network/pkg/cryptography/signature"
    "github.com/synnergy_network/pkg/network/rpc"
    "github.com/synnergy_network/pkg/operations/blockchain_maintenance"
    "github.com/synnergy_network/pkg/security/network_security"
)

// TransactionService manages transactions within the blockchain network.
type TransactionService struct {
    transactions    sync.Map // map[string]Transaction
    blockchain      *chain.Blockchain
    auditService    *audit_trails.AuditTrailService
    monitoringService *transaction_monitoring.TransactionMonitoringService
}

// NewTransactionService initializes and returns a new TransactionService.
func NewTransactionService(blockchain *chain.Blockchain, auditService *audit_trails.AuditTrailService, monitoringService *transaction_monitoring.TransactionMonitoringService) *TransactionService {
    return &TransactionService{
        blockchain:      blockchain,
        auditService:    auditService,
        monitoringService: monitoringService,
    }
}

// CancelTransaction cancels a transaction by its ID.
func (ts *TransactionService) CancelTransaction(txID string, userPrivateKey string) error {
    // Retrieve the transaction
    tx, ok := ts.getTransactionByID(txID)
    if !ok {
        return errors.New("transaction not found")
    }

    // Verify the transaction is not yet confirmed
    if ts.blockchain.IsTransactionConfirmed(txID) {
        return errors.New("transaction already confirmed")
    }

    // Verify user authorization
    if !ts.verifyUserAuthorization(tx, userPrivateKey) {
        return errors.New("unauthorized cancellation attempt")
    }

    // Mark the transaction as cancelled
    tx.Status = "cancelled"
    ts.transactions.Store(txID, tx)

    // Record the cancellation in the audit trail
    ts.auditService.RecordCancellation(txID, tx.From, tx.To, tx.Amount, time.Now())

    // Notify monitoring service of the cancellation
    ts.monitoringService.RecordTransactionCancellation(txID, tx.From, tx.To, tx.Amount)

    // Remove transaction from blockchain
    ts.blockchain.RemoveTransaction(txID)

    return nil
}

// getTransactionByID retrieves a transaction by its ID.
func (ts *TransactionService) getTransactionByID(txID string) (Transaction, bool) {
    tx, ok := ts.transactions.Load(txID)
    if !ok {
        return Transaction{}, false
    }
    return tx.(Transaction), true
}

// verifyUserAuthorization verifies that the user is authorized to cancel the transaction.
func (ts *TransactionService) verifyUserAuthorization(tx Transaction, userPrivateKey string) bool {
    // Get public key from private key
    userPublicKey := keys.GetPublicKeyFromPrivateKey(userPrivateKey)

    // Verify the user is the sender of the transaction
    return tx.From == userPublicKey
}

// Transaction represents a blockchain transaction.
type Transaction struct {
    ID        string  `json:"id"`
    From      string  `json:"from"`
    To        string  `json:"to"`
    Amount    float64 `json:"amount"`
    Timestamp int64   `json:"timestamp"`
    Signature string  `json:"signature"`
    Status    string  `json:"status"`
}

// BlockchainService interacts with the blockchain.
type BlockchainService struct {
    chain *chain.Blockchain
}

// IsTransactionConfirmed checks if a transaction is confirmed.
func (bs *BlockchainService) IsTransactionConfirmed(txID string) bool {
    // Mock implementation - replace with actual logic
    return false
}

// RemoveTransaction removes a transaction from the blockchain.
func (bs *BlockchainService) RemoveTransaction(txID string) {
    // Mock implementation - replace with actual logic
}

// AuditTrailService manages audit trails.
type AuditTrailService struct{}

// RecordCancellation records a transaction cancellation in the audit trail.
func (ats *AuditTrailService) RecordCancellation(txID, from, to string, amount float64, timestamp time.Time) {
    // Mock implementation - replace with actual logic
}

// TransactionMonitoringService monitors transactions.
type TransactionMonitoringService struct{}

// RecordTransactionCancellation records a transaction cancellation.
func (tms *TransactionMonitoringService) RecordTransactionCancellation(txID, from, to string, amount float64) {
    // Mock implementation - replace with actual logic
}

// GetPublicKeyFromPrivateKey retrieves the public key from a private key.
func GetPublicKeyFromPrivateKey(privateKey string) string {
    // Mock implementation - replace with actual logic
    return privateKey
}
package transaction

import (
    "encoding/json"
    "errors"
    "fmt"
    "math/rand"
    "os"
    "sync"

    "github.com/google/uuid"
    "github.com/synnergy_network/pkg/blockchain"
    "github.com/synnergy_network/pkg/cryptography/encryption"
    "github.com/synnergy_network/pkg/cryptography/hash"
    "github.com/synnergy_network/pkg/cryptography/signature"
    "github.com/synnergy_network/pkg/identity_services/access_control"
    "github.com/synnergy_network/pkg/identity_services/identity_management"
    "github.com/synnergy_network/pkg/identity_services/privacy_management"
    "github.com/synnergy_network/pkg/security/network_security"
    "github.com/synnergy_network/pkg/transaction/transaction_types"
    "github.com/synnergy_network/pkg/wallet/storage"
    "github.com/synnergy_network/pkg/wallet/utils"
    "golang.org/x/crypto/scrypt"
)

// TransactionService manages blockchain transactions
type TransactionService struct {
    transactions map[string]transaction_types.Transaction
    mu           sync.RWMutex
    filePath     string
}

// NewTransactionService initializes and returns a new TransactionService
func NewTransactionService(filePath string) *TransactionService {
    ts := &TransactionService{
        transactions: make(map[string]transaction_types.Transaction),
        filePath:     filePath,
    }
    ts.loadFromFile()
    return ts
}

// AddTransaction adds a new transaction to the storage
func (ts *TransactionService) AddTransaction(from, to string, amount, transactionFee float64, timestamp int64, signature string) (string, error) {
    ts.mu.Lock()
    defer ts.mu.Unlock()

    id := uuid.New().String()
    transaction := transaction_types.Transaction{
        ID:             id,
        From:           from,
        To:             to,
        Amount:         amount,
        Timestamp:      timestamp,
        Signature:      signature,
        TransactionFee: transactionFee,
        Private:        false,
    }
    ts.transactions[id] = transaction
    err := ts.saveToFile()
    if err != nil {
        return "", err
    }
    return id, nil
}

// ConvertToPrivateTransaction converts a regular transaction to a private transaction
func (ts *TransactionService) ConvertToPrivateTransaction(id, passphrase string) error {
    ts.mu.Lock()
    defer ts.mu.Unlock()

    transaction, exists := ts.transactions[id]
    if !exists {
        return errors.New("transaction not found")
    }

    if transaction.Private {
        return errors.New("transaction is already private")
    }

    encryptedAmount, zeroKnowledgeProof, err := ts.encryptAndProve(transaction.Amount, passphrase)
    if err != nil {
        return err
    }

    privateTransaction := transaction_types.PrivateTransaction{
        Transaction:        transaction,
        EncryptedAmount:    encryptedAmount,
        ZeroKnowledgeProof: zeroKnowledgeProof,
    }

    transaction.Private = true
    transaction.PrivateDetails = &privateTransaction

    ts.transactions[id] = transaction
    return ts.saveToFile()
}

func (ts *TransactionService) encryptAndProve(amount float64, passphrase string) (string, string, error) {
    // Encrypt the amount
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", "", err
    }
    derivedKey, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
    if err != nil {
        return "", "", err
    }
    encryptedAmount, err := encryption.EncryptAES([]byte(fmt.Sprintf("%f", amount)), derivedKey)
    if err != nil {
        return "", "", err
    }

    // Generate a zero-knowledge proof (mock implementation)
    zeroKnowledgeProof := "zkp_mock_proof"

    return encryptedAmount, zeroKnowledgeProof, nil
}

// GetTransaction retrieves a transaction by ID
func (ts *TransactionService) GetTransaction(id string) (transaction_types.Transaction, error) {
    ts.mu.RLock()
    defer ts.mu.RUnlock()

    transaction, exists := ts.transactions[id]
    if !exists {
        return transaction_types.Transaction{}, errors.New("transaction not found")
    }
    return transaction, nil
}

// GetAllTransactions retrieves all transactions
func (ts *TransactionService) GetAllTransactions() ([]transaction_types.Transaction, error) {
    ts.mu.RLock()
    defer ts.mu.RUnlock()

    var transactions []transaction_types.Transaction
    for _, transaction := range ts.transactions {
        transactions = append(transactions, transaction)
    }
    return transactions, nil
}

// saveToFile saves the current state of transactions to a file
func (ts *TransactionService) saveToFile() error {
    data, err := json.Marshal(ts.transactions)
    if err != nil {
        return err
    }
    return os.WriteFile(ts.filePath, data, 0644)
}

// loadFromFile loads the transactions from a file
func (ts *TransactionService) loadFromFile() error {
    file, err := os.ReadFile(ts.filePath)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return nil // File does not exist, no transactions to load
        }
        return err
    }
    return json.Unmarshal(file, &ts.transactions)
}
package transaction

import (
	"sync"
	"time"

	"github.com/synnergy_network/pkg/layer0/core/blockchain"
	"github.com/synnergy_network/pkg/layer0/core/wallet"
)

// DynamicFeeAdjustmentService manages dynamic fee adjustments based on network conditions.
type DynamicFeeAdjustmentService struct {
	blockchainService *blockchain.BlockchainService
	walletService     *wallet.WalletService
	baseFee           float64
	feeMultiplier     float64
	mu                sync.Mutex
}

// NewDynamicFeeAdjustmentService initializes and returns a new DynamicFeeAdjustmentService.
func NewDynamicFeeAdjustmentService(blockchainService *blockchain.BlockchainService, walletService *wallet.WalletService, baseFee, feeMultiplier float64) *DynamicFeeAdjustmentService {
	return &DynamicFeeAdjustmentService{
		blockchainService: blockchainService,
		walletService:     walletService,
		baseFee:           baseFee,
		feeMultiplier:     feeMultiplier,
	}
}

// AdjustFee dynamically adjusts transaction fees based on network congestion.
func (dfas *DynamicFeeAdjustmentService) AdjustFee() float64 {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	congestionLevel := dfas.blockchainService.GetNetworkCongestionLevel()
	return dfas.baseFee + (dfas.baseFee * dfas.feeMultiplier * congestionLevel)
}

// SetBaseFee sets the base fee for transactions.
func (dfas *DynamicFeeAdjustmentService) SetBaseFee(baseFee float64) {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	dfas.baseFee = baseFee
}

// SetFeeMultiplier sets the fee multiplier for transactions.
func (dfas *DynamicFeeAdjustmentService) SetFeeMultiplier(feeMultiplier float64) {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	dfas.feeMultiplier = feeMultiplier
}

// MonitorAndAdjustFees continuously monitors the network and adjusts fees in real-time.
func (dfas *DynamicFeeAdjustmentService) MonitorAndAdjustFees(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			dfas.AdjustFee()
		}
	}()
}

// FeeEstimator provides a fee estimate for a given transaction based on current network conditions.
func (dfas *DynamicFeeAdjustmentService) FeeEstimator(transactionSize int64) float64 {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	congestionLevel := dfas.blockchainService.GetNetworkCongestionLevel()
	estimatedFee := dfas.baseFee + (dfas.baseFee * dfas.feeMultiplier * congestionLevel)
	return estimatedFee * float64(transactionSize)
}

// UserDefinedFees allows users to set custom fees for their transactions.
func (dfas *DynamicFeeAdjustmentService) UserDefinedFees(walletAddress string, customFee float64) error {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	// Logic to set custom fee for a specific user's wallet address
	// Ensure custom fee is within allowed limits and conditions
	return nil
}

// CalculateTransactionFee calculates the appropriate fee for a given transaction based on its size and priority.
func (dfas *DynamicFeeAdjustmentService) CalculateTransactionFee(transaction *blockchain.Transaction) float64 {
	dfas.mu.Lock()
	defer dfas.mu.Unlock()
	// Retrieve transaction size and user-defined priority
	transactionSize := transaction.Size()
	priority := transaction.Priority()
	// Base fee calculation
	baseFee := dfas.FeeEstimator(transactionSize)
	// Adjust fee based on priority (high, medium, low)
	var priorityMultiplier float64
	switch priority {
	case "high":
		priorityMultiplier = 1.5
	case "medium":
		priorityMultiplier = 1.0
	case "low":
		priorityMultiplier = 0.5
	default:
		priorityMultiplier = 1.0
	}
	return baseFee * priorityMultiplier
}

// NotifyUsersOfFeeChanges sends notifications to users about fee adjustments.
func (dfas *DynamicFeeAdjustmentService) NotifyUsersOfFeeChanges() {
	// Logic to send notifications (email, SMS, in-app alerts) to users
	// Notify users of significant fee changes based on network conditions
}

// IntegrateWithWalletService ensures the dynamic fee adjustment integrates with the wallet service.
func (dfas *DynamicFeeAdjustmentService) IntegrateWithWalletService() {
	// Logic to integrate dynamic fee adjustment with wallet service
	// Ensure wallet transactions use the dynamically adjusted fees
}

// EnableRealTimeFeeUpdates enables real-time fee updates for the wallet service.
func (dfas *DynamicFeeAdjustmentService) EnableRealTimeFeeUpdates() {
	dfas.walletService.SetFeeAdjustmentCallback(dfas.CalculateTransactionFee)
}

// NewFeeEstimator initializes and returns a new fee estimator service.
func NewFeeEstimator(blockchainService *blockchain.BlockchainService, walletService *wallet.WalletService) *DynamicFeeAdjustmentService {
	return NewDynamicFeeAdjustmentService(blockchainService, walletService, 0.0001, 1.0)
}
package transaction

import (
    "sync"
    "time"
    "github.com/synnergy_network/pkg/consensus/proof_of_work"
    "github.com/synnergy_network/pkg/blockchain/chain"
    "github.com/synnergy_network/pkg/network/network_monitoring"
    "github.com/synnergy_network/pkg/transaction/fee"
    "github.com/synnergy_network/pkg/transaction/transaction_types"
    "math"
)

// DynamicFeeAdjustmentService manages dynamic fee adjustments based on network conditions.
type DynamicFeeAdjustmentService struct {
    blockchainService *chain.BlockchainService
    networkMonitor    *network_monitoring.NetworkMonitor
    baseFee           float64
    feeMultiplier     float64
    mu                sync.Mutex
}

// NewDynamicFeeAdjustmentService initializes and returns a new DynamicFeeAdjustmentService.
func NewDynamicFeeAdjustmentService(blockchainService *chain.BlockchainService, networkMonitor *network_monitoring.NetworkMonitor, baseFee, feeMultiplier float64) *DynamicFeeAdjustmentService {
    return &DynamicFeeAdjustmentService{
        blockchainService: blockchainService,
        networkMonitor:    networkMonitor,
        baseFee:           baseFee,
        feeMultiplier:     feeMultiplier,
    }
}

// AdjustFee dynamically adjusts transaction fees based on network congestion.
func (dfas *DynamicFeeAdjustmentService) AdjustFee() float64 {
    dfas.mu.Lock()
    defer dfas.mu.Unlock()

    congestionLevel := dfas.networkMonitor.GetNetworkCongestionLevel()
    return dfas.baseFee + (dfas.baseFee * dfas.feeMultiplier * congestionLevel)
}

// MonitorNetworkConditions continuously monitors network conditions and adjusts fees accordingly.
func (dfas *DynamicFeeAdjustmentService) MonitorNetworkConditions() {
    for {
        currentFee := dfas.AdjustFee()
        fee.SetCurrentTransactionFee(currentFee)
        time.Sleep(1 * time.Minute) // Adjust fees every minute
    }
}

// GetRecommendedFee provides the recommended fee based on current network conditions.
func (dfas *DynamicFeeAdjustmentService) GetRecommendedFee(transactionType transaction_types.TransactionType) float64 {
    currentFee := fee.GetCurrentTransactionFee()
    switch transactionType {
    case transaction_types.HighPriority:
        return currentFee * 1.5
    case transaction_types.LowPriority:
        return currentFee * 0.75
    default:
        return currentFee
    }
}

// RealTimeAdjustment triggers immediate fee adjustment based on sudden network changes.
func (dfas *DynamicFeeAdjustmentService) RealTimeAdjustment(newBaseFee, newMultiplier float64) {
    dfas.mu.Lock()
    defer dfas.mu.Unlock()
    
    dfas.baseFee = newBaseFee
    dfas.feeMultiplier = newMultiplier
    currentFee := dfas.AdjustFee()
    fee.SetCurrentTransactionFee(currentFee)
}

// ValidateFee ensures that the provided fee is sufficient based on current network conditions.
func (dfas *DynamicFeeAdjustmentService) ValidateFee(providedFee float64, transactionType transaction_types.TransactionType) error {
    recommendedFee := dfas.GetRecommendedFee(transactionType)
    if providedFee < recommendedFee {
        return fmt.Errorf("provided fee is too low, recommended fee is: %f", recommendedFee)
    }
    return nil
}
package transaction

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/blockchain"
	"github.com/synnergy_network/pkg/cryptography/encryption"
	"github.com/synnergy_network/pkg/cryptography/signature"
	"github.com/synnergy_network/pkg/transaction/ledger"
	"github.com/synnergy_network/pkg/transaction/validation"
	"github.com/synnergy_network/pkg/wallet/core"
)

// ReceiveTransactionService handles the logic for receiving transactions.
type ReceiveTransactionService struct {
	mu           sync.Mutex
	ledger       *ledger.Ledger
	validation   *validation.TransactionValidator
	blockchain   *blockchain.Blockchain
	encryption   *encryption.EncryptionService
	signature    *signature.SignatureService
	wallet       *core.WalletCore
}

// NewReceiveTransactionService initializes and returns a new ReceiveTransactionService.
func NewReceiveTransactionService(ledger *ledger.Ledger, validator *validation.TransactionValidator, blockchain *blockchain.Blockchain, encryption *encryption.EncryptionService, signature *signature.SignatureService, wallet *core.WalletCore) *ReceiveTransactionService {
	return &ReceiveTransactionService{
		ledger:     ledger,
		validation: validator,
		blockchain: blockchain,
		encryption: encryption,
		signature:  signature,
		wallet:     wallet,
	}
}

// ReceiveTransaction processes an incoming transaction and updates the wallet balance accordingly.
func (rts *ReceiveTransactionService) ReceiveTransaction(tx *ledger.Transaction) error {
	rts.mu.Lock()
	defer rts.mu.Unlock()

	// Validate the transaction
	if err := rts.validation.ValidateTransaction(tx); err != nil {
		return err
	}

	// Decrypt the transaction if necessary
	if tx.Encrypted {
		decryptedData, err := rts.encryption.Decrypt(tx.Data, tx.EncryptionKey)
		if err != nil {
			return err
		}
		tx.Data = decryptedData
	}

	// Verify the transaction signature
	if err := rts.signature.VerifySignature(tx.From, tx.Signature, tx.Data); err != nil {
		return err
	}

	// Add the transaction to the ledger
	if err := rts.ledger.AddTransaction(tx); err != nil {
		return err
	}

	// Update the wallet balance
	rts.wallet.UpdateBalance(tx.To, tx.Amount, true)

	// Notify the user
	rts.notifyUser(tx)

	return nil
}

// notifyUser sends a notification to the user about the received transaction.
func (rts *ReceiveTransactionService) notifyUser(tx *ledger.Transaction) {
	// Implementation of user notification logic (e.g., email, SMS, push notification)
	log.Printf("Transaction received: %s", tx.ID)
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string `json:"id"`
	From          string `json:"from"`
	To            string `json:"to"`
	Amount        float64 `json:"amount"`
	Timestamp     int64   `json:"timestamp"`
	Signature     string  `json:"signature"`
	Encrypted     bool    `json:"encrypted"`
	EncryptionKey string  `json:"encryption_key"`
	Data          []byte  `json:"data"`
}

// Ledger handles the storage and retrieval of transactions
type Ledger struct {
	mu           sync.RWMutex
	transactions map[string]*Transaction
}

// NewLedger initializes and returns a new Ledger.
func NewLedger() *Ledger {
	return &Ledger{
		transactions: make(map[string]*Transaction),
	}
}

// AddTransaction adds a new transaction to the ledger.
func (l *Ledger) AddTransaction(tx *Transaction) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.transactions[tx.ID]; exists {
		return errors.New("transaction already exists")
	}

	l.transactions[tx.ID] = tx
	return nil
}

// GetTransaction retrieves a transaction by ID.
func (l *Ledger) GetTransaction(id string) (*Transaction, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	tx, exists := l.transactions[id]
	if !exists {
		return nil, errors.New("transaction not found")
	}
	return tx, nil
}

// TransactionValidator validates the integrity and authenticity of transactions.
type TransactionValidator struct{}

// NewTransactionValidator initializes and returns a new TransactionValidator.
func NewTransactionValidator() *TransactionValidator {
	return &TransactionValidator{}
}

// ValidateTransaction validates a transaction.
func (tv *TransactionValidator) ValidateTransaction(tx *Transaction) error {
	// Implement validation logic (e.g., checking for sufficient balance, double-spending prevention)
	return nil
}

// Blockchain represents the blockchain network.
type Blockchain struct{}

// EncryptionService handles encryption and decryption of data.
type EncryptionService struct{}

// Decrypt decrypts the given data using the provided encryption key.
func (es *EncryptionService) Decrypt(data []byte, key string) ([]byte, error) {
	// Implement decryption logic (e.g., using AES, Scrypt, or Argon2)
	return data, nil
}

// SignatureService handles the verification of digital signatures.
type SignatureService struct{}

// VerifySignature verifies the signature of the given data.
func (ss *SignatureService) VerifySignature(publicKey, signature string, data []byte) error {
	// Implement signature verification logic
	return nil
}

// WalletCore represents the core wallet functionalities.
type WalletCore struct{}

// UpdateBalance updates the balance of the wallet.
func (wc *WalletCore) UpdateBalance(address string, amount float64, add bool) {
	// Implement balance update logic
}

package transaction

import (
    "errors"
    "log"
    "time"
    "sync"

    "github.com/synnergy_network/pkg/transaction/transaction_types"
    "github.com/synnergy_network/pkg/transaction/validation"
    "github.com/synnergy_network/pkg/transaction/history"
    "github.com/synnergy_network/pkg/cryptography/encryption"
    "github.com/synnergy_network/pkg/cryptography/signature"
    "github.com/synnergy_network/pkg/compliance/transaction_monitoring"
)

// ReportService handles the reporting of suspicious transactions.
type ReportService struct {
    historyService   *history.HistoryService
    validationService *validation.ValidationService
    monitoringService *transaction_monitoring.MonitoringService
    reports          sync.Map // map[string]Report
}

// Report represents a report of a suspicious transaction.
type Report struct {
    ID          string
    Transaction transaction_types.Transaction
    Reason      string
    ReportedAt  time.Time
    Status      string // "Pending", "Reviewed", "Resolved"
}

// NewReportService initializes and returns a new ReportService.
func NewReportService(historyService *history.HistoryService, validationService *validation.ValidationService, monitoringService *transaction_monitoring.MonitoringService) *ReportService {
    return &ReportService{
        historyService:   historyService,
        validationService: validationService,
        monitoringService: monitoringService,
    }
}

// ReportTransaction reports a suspicious transaction.
func (rs *ReportService) ReportTransaction(txID, reason string) (string, error) {
    tx, err := rs.historyService.GetTransaction(txID)
    if err != nil {
        return "", errors.New("transaction not found")
    }

    if !rs.validationService.ValidateTransaction(tx) {
        return "", errors.New("transaction validation failed")
    }

    reportID := generateReportID()
    report := Report{
        ID:          reportID,
        Transaction: tx,
        Reason:      reason,
        ReportedAt:  time.Now(),
        Status:      "Pending",
    }

    rs.reports.Store(reportID, report)
    log.Printf("Transaction reported: %v", report)
    rs.monitoringService.NotifySuspiciousActivity(tx)

    return reportID, nil
}

// ReviewReport allows the review of a reported transaction.
func (rs *ReportService) ReviewReport(reportID, status, reviewer string) error {
    value, ok := rs.reports.Load(reportID)
    if !ok {
        return errors.New("report not found")
    }

    report := value.(Report)
    if report.Status != "Pending" {
        return errors.New("report already reviewed")
    }

    report.Status = status
    rs.reports.Store(reportID, report)
    log.Printf("Report reviewed by %s: %v", reviewer, report)

    return nil
}

// GetReport retrieves a report by ID.
func (rs *ReportService) GetReport(reportID string) (Report, error) {
    value, ok := rs.reports.Load(reportID)
    if !ok {
        return Report{}, errors.New("report not found")
    }
    return value.(Report), nil
}

// generateReportID generates a unique report ID.
func generateReportID() string {
    return encryption.GenerateUUID()
}

// MonitoringService implements the transaction_monitoring.MonitoringService interface.
type MonitoringService struct{}

// NotifySuspiciousActivity sends a notification for suspicious activity.
func (ms *MonitoringService) NotifySuspiciousActivity(tx transaction_types.Transaction) {
    log.Printf("Suspicious activity detected: %v", tx)
    // Implement notification logic (e.g., send an email, push notification, etc.)
}

// HistoryService implements the history.HistoryService interface.
type HistoryService struct{}

// GetTransaction retrieves a transaction by ID.
func (hs *HistoryService) GetTransaction(txID string) (transaction_types.Transaction, error) {
    // Implement logic to retrieve the transaction from history
    return transaction_types.Transaction{}, nil
}

// ValidationService implements the validation.ValidationService interface.
type ValidationService struct{}

// ValidateTransaction validates a transaction.
func (vs *ValidationService) ValidateTransaction(tx transaction_types.Transaction) bool {
    // Implement logic to validate the transaction
    return true
}

// Transaction represents a simplified transaction structure.
type Transaction struct {
    ID            string
    From          string
    To            string
    Amount        float64
    Timestamp     time.Time
    Signature     string
    TransactionFee float64
}

package transaction

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "math/big"
    "sync"
    "time"

    "github.com/synnergy_network/blockchain/address"
    "github.com/synnergy_network/blockchain/crypto"
    "github.com/synnergy_network/blockchain/transaction_types"
    "github.com/synnergy_network/compliance/fraud_detection_and_risk_management"
    "github.com/synnergy_network/network/p2p"
    "github.com/synnergy_network/network/rpc"
    "github.com/synnergy_network/wallet/authentication"
    "github.com/synnergy_network/wallet/storage"
    "github.com/synnergy_network/blockchain/transaction/fee"
)

type SendTransactionService struct {
    privateKey *ecdsa.PrivateKey
    mutex      sync.Mutex
    storage    *storage.TransactionStorage
    network    *p2p.Network
    feeService *fee.FeeService
}

// NewSendTransactionService initializes a new SendTransactionService.
func NewSendTransactionService(privateKey *ecdsa.PrivateKey, storage *storage.TransactionStorage, network *p2p.Network, feeService *fee.FeeService) *SendTransactionService {
    return &SendTransactionService{
        privateKey: privateKey,
        storage:    storage,
        network:    network,
        feeService: feeService,
    }
}

// Transaction represents a blockchain transaction.
type Transaction struct {
    ID            string          `json:"id"`
    From          string          `json:"from"`
    To            string          `json:"to"`
    Amount        float64         `json:"amount"`
    Timestamp     int64           `json:"timestamp"`
    Signature     string          `json:"signature"`
    TransactionFee float64        `json:"transaction_fee"`
    TransactionType transaction_types.TransactionType `json:"transaction_type"`
}

// CreateTransaction creates a new transaction.
func (sts *SendTransactionService) CreateTransaction(from, to string, amount float64) (*Transaction, error) {
    sts.mutex.Lock()
    defer sts.mutex.Unlock()

    // Validate the transaction
    if from == "" || to == "" {
        return nil, errors.New("from and to addresses cannot be empty")
    }

    if amount <= 0 {
        return nil, errors.New("amount must be greater than zero")
    }

    // Check for sufficient balance
    balance, err := sts.storage.GetBalance(from)
    if err != nil || balance < amount {
        return nil, errors.New("insufficient balance")
    }

    // Calculate transaction fee
    fee, err := sts.feeService.CalculateFee(amount)
    if err != nil {
        return nil, err
    }

    if balance < (amount + fee) {
        return nil, errors.New("insufficient balance to cover transaction fee")
    }

    txID := generateTransactionID(from, to, amount, fee)
    timestamp := time.Now().Unix()

    tx := &Transaction{
        ID:            txID,
        From:          from,
        To:            to,
        Amount:        amount,
        Timestamp:     timestamp,
        TransactionFee: fee,
        TransactionType: transaction_types.Standard,
    }

    // Sign the transaction
    signature, err := sts.signTransaction(tx)
    if err != nil {
        return nil, err
    }

    tx.Signature = signature

    // Save the transaction to storage
    err = sts.storage.AddTransaction(tx)
    if err != nil {
        return nil, err
    }

    return tx, nil
}

// SendTransaction sends the transaction to the network.
func (sts *SendTransactionService) SendTransaction(tx *Transaction) error {
    // Perform fraud detection and risk management
    if err := fraud_detection_and_risk_management.ValidateTransaction(tx); err != nil {
        return err
    }

    // Broadcast the transaction to the network
    if err := sts.network.BroadcastTransaction(tx); err != nil {
        return err
    }

    // Update balances in storage
    if err := sts.storage.UpdateBalance(tx.From, -tx.Amount-tx.TransactionFee); err != nil {
        return err
    }
    if err := sts.storage.UpdateBalance(tx.To, tx.Amount); err != nil {
        return err
    }

    return nil
}

// signTransaction signs the transaction with the private key.
func (sts *SendTransactionService) signTransaction(tx *Transaction) (string, error) {
    txData, err := json.Marshal(tx)
    if err != nil {
        return "", err
    }

    hash := sha256.Sum256(txData)
    r, s, err := ecdsa.Sign(crypto.RandomReader, sts.privateKey, hash[:])
    if err != nil {
        return "", err
    }

    signature := r.Bytes()
    signature = append(signature, s.Bytes()...)

    return fmt.Sprintf("%x", signature), nil
}

// generateTransactionID generates a unique ID for the transaction.
func generateTransactionID(from, to string, amount, fee float64) string {
    txData := from + to + fmt.Sprintf("%f%f", amount, fee)
    hash := sha256.Sum256([]byte(txData))
    return fmt.Sprintf("%x", hash)
}
package transaction

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "math/big"
    "sync"
    "time"

    "github.com/synnergy_network/blockchain/crypto"
    "github.com/synnergy_network/blockchain/transaction/fee"
    "github.com/synnergy_network/blockchain/transaction/validation"
    "github.com/synnergy_network/wallet/core"
    "github.com/synnergy_network/wallet/storage"
    "github.com/synnergy_network/consensus/proof_of_stake"
)

type Transaction struct {
    ID            string  `json:"id"`
    From          string  `json:"from"`
    To            string  `json:"to"`
    Amount        float64 `json:"amount"`
    Timestamp     int64   `json:"timestamp"`
    Signature     string  `json:"signature"`
    TransactionFee float64 `json:"transaction_fee"`
}

type Wallet struct {
    PrivateKey *ecdsa.PrivateKey
    Address    string
}

type TransactionManager struct {
    transactions map[string]Transaction
    mu           sync.RWMutex
    filePath     string
}

func NewTransactionManager(filePath string) *TransactionManager {
    return &TransactionManager{
        transactions: make(map[string]Transaction),
        filePath:     filePath,
    }
}

func (tm *TransactionManager) AddTransaction(wallet *Wallet, to string, amount float64) (string, error) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    // Check if the wallet has sufficient balance
    balance, err := storage.GetBalance(wallet.Address)
    if err != nil {
        return "", err
    }
    if balance < amount {
        return "", errors.New("insufficient balance")
    }

    // Generate transaction ID
    id := generateTransactionID()

    // Calculate transaction fee
    transactionFee, err := fee.CalculateFee(amount)
    if err != nil {
        return "", err
    }

    // Create transaction
    transaction := Transaction{
        ID:            id,
        From:          wallet.Address,
        To:            to,
        Amount:        amount,
        Timestamp:     time.Now().Unix(),
        TransactionFee: transactionFee,
    }

    // Sign the transaction
    signature, err := signTransaction(wallet.PrivateKey, transaction)
    if err != nil {
        return "", err
    }
    transaction.Signature = signature

    // Validate the transaction
    if err := validation.ValidateTransaction(transaction); err != nil {
        return "", err
    }

    // Add transaction to the manager and storage
    tm.transactions[id] = transaction
    if err := storage.SaveTransaction(tm.filePath, transaction); err != nil {
        return "", err
    }

    // Update balances
    if err := storage.UpdateBalance(wallet.Address, -amount-transactionFee); err != nil {
        return "", err
    }
    if err := storage.UpdateBalance(to, amount); err != nil {
        return "", err
    }

    return id, nil
}

func generateTransactionID() string {
    id := make([]byte, 16)
    rand.Read(id)
    return hex.EncodeToString(id)
}

func signTransaction(privateKey *ecdsa.PrivateKey, transaction Transaction) (string, error) {
    data := transaction.From + transaction.To + strconv.FormatFloat(transaction.Amount, 'f', 6, 64) + strconv.FormatInt(transaction.Timestamp, 10)
    hash := sha256.Sum256([]byte(data))

    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        return "", err
    }

    signature := r.Bytes()
    signature = append(signature, s.Bytes()...)

    return hex.EncodeToString(signature), nil
}

func verifyTransactionSignature(publicKey *ecdsa.PublicKey, transaction Transaction) bool {
    data := transaction.From + transaction.To + strconv.FormatFloat(transaction.Amount, 'f', 6, 64) + strconv.FormatInt(transaction.Timestamp, 10)
    hash := sha256.Sum256([]byte(data))

    signatureBytes, err := hex.DecodeString(transaction.Signature)
    if err != nil {
        return false
    }

    r := big.Int{}
    s := big.Int{}
    r.SetBytes(signatureBytes[:len(signatureBytes)/2])
    s.SetBytes(signatureBytes[len(signatureBytes)/2:])

    return ecdsa.Verify(publicKey, hash[:], &r, &s)
}

func (tm *TransactionManager) GetTransaction(id string) (Transaction, error) {
    tm.mu.RLock()
    defer tm.mu.RUnlock()

    transaction, exists := tm.transactions[id]
    if !exists {
        return Transaction{}, errors.New("transaction not found")
    }
    return transaction, nil
}

func (tm *TransactionManager) GetTransactionsByAddress(address string) ([]Transaction, error) {
    tm.mu.RLock()
    defer tm.mu.RUnlock()

    var transactions []Transaction
    for _, transaction := range tm.transactions {
        if transaction.From == address || transaction.To == address {
            transactions = append(transactions, transaction)
        }
    }
    return transactions, nil
}

func (tm *TransactionManager) GetAllTransactions() ([]Transaction, error) {
    tm.mu.RLock()
    defer tm.mu.RUnlock()

    var transactions []Transaction
    for _, transaction := range tm.transactions {
        transactions = append(transactions, transaction)
    }
    return transactions, nil
}

func (tm *TransactionManager) DeleteTransaction(id string) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    if _, exists := tm.transactions[id]; !exists {
        return errors.New("transaction not found")
    }
    delete(tm.transactions, id)
    return storage.DeleteTransaction(tm.filePath, id)
}
package transaction

import (
    "encoding/json"
    "errors"
    "os"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/synnergy_network/blockchain/transaction/fee"
    "github.com/synnergy_network/blockchain/crypto"
    "github.com/synnergy_network/blockchain/storage"
    "github.com/synnergy_network/blockchain/transaction/validation"
    "github.com/synnergy_network/blockchain/transaction/types"
    "github.com/synnergy_network/blockchain/utils"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID            string  `json:"id"`
    From          string  `json:"from"`
    To            string  `json:"to"`
    Amount        float64 `json:"amount"`
    Timestamp     int64   `json:"timestamp"`
    Signature     string  `json:"signature"`
    TransactionFee float64 `json:"transaction_fee"`
    Status        string  `json:"status"` // pending, confirmed, failed
    Private       bool    `json:"private"`
}

// TransactionHistory manages the storage and retrieval of transaction history
type TransactionHistory struct {
    transactions map[string]Transaction
    mu           sync.RWMutex
    filePath     string
}

// NewTransactionHistory initializes and returns a new TransactionHistory
func NewTransactionHistory(filePath string) *TransactionHistory {
    th := &TransactionHistory{
        transactions: make(map[string]Transaction),
        filePath:     filePath,
    }
    th.loadFromFile()
    return th
}

// AddTransaction adds a new transaction to the history
func (th *TransactionHistory) AddTransaction(from, to string, amount, transactionFee float64, private bool) (string, error) {
    th.mu.Lock()
    defer th.mu.Unlock()

    id := uuid.New().String()
    timestamp := time.Now().Unix()
    signature, err := crypto.SignTransaction(from, to, amount, transactionFee, timestamp)
    if err != nil {
        return "", err
    }

    transaction := Transaction{
        ID:            id,
        From:          from,
        To:            to,
        Amount:        amount,
        Timestamp:     timestamp,
        Signature:     signature,
        TransactionFee: transactionFee,
        Status:        "pending",
        Private:       private,
    }

    // Validate the transaction before adding
    if err := validation.ValidateTransaction(transaction); err != nil {
        return "", err
    }

    // Encrypt transaction if it's private
    if private {
        transaction, err = crypto.EncryptTransaction(transaction)
        if err != nil {
            return "", err
        }
    }

    th.transactions[id] = transaction
    err = th.saveToFile()
    if err != nil {
        return "", err
    }
    return id, nil
}

// GetTransaction retrieves a transaction by ID
func (th *TransactionHistory) GetTransaction(id string) (Transaction, error) {
    th.mu.RLock()
    defer th.mu.RUnlock()

    transaction, exists := th.transactions[id]
    if !exists {
        return Transaction{}, errors.New("transaction not found")
    }

    // Decrypt transaction if it's private
    if transaction.Private {
        decryptedTransaction, err := crypto.DecryptTransaction(transaction)
        if err != nil {
            return Transaction{}, err
        }
        return decryptedTransaction, nil
    }

    return transaction, nil
}

// GetTransactionsByAddress retrieves all transactions associated with a given address
func (th *TransactionHistory) GetTransactionsByAddress(address string) ([]Transaction, error) {
    th.mu.RLock()
    defer th.mu.RUnlock()

    var transactions []Transaction
    for _, transaction := range th.transactions {
        if transaction.From == address || transaction.To == address {
            if transaction.Private {
                decryptedTransaction, err := crypto.DecryptTransaction(transaction)
                if err != nil {
                    return nil, err
                }
                transactions = append(transactions, decryptedTransaction)
            } else {
                transactions = append(transactions, transaction)
            }
        }
    }
    return transactions, nil
}

// GetAllTransactions retrieves all transactions
func (th *TransactionHistory) GetAllTransactions() ([]Transaction, error) {
    th.mu.RLock()
    defer th.mu.RUnlock()

    var transactions []Transaction
    for _, transaction := range th.transactions {
        if transaction.Private {
            decryptedTransaction, err := crypto.DecryptTransaction(transaction)
            if err != nil {
                return nil, err
            }
            transactions = append(transactions, decryptedTransaction)
        } else {
            transactions = append(transactions, transaction)
        }
    }
    return transactions, nil
}

// UpdateTransactionStatus updates the status of a transaction
func (th *TransactionHistory) UpdateTransactionStatus(id, status string) error {
    th.mu.Lock()
    defer th.mu.Unlock()

    transaction, exists := th.transactions[id]
    if !exists {
        return errors.New("transaction not found")
    }

    transaction.Status = status
    th.transactions[id] = transaction
    return th.saveToFile()
}

// DeleteTransaction deletes a transaction by ID
func (th *TransactionHistory) DeleteTransaction(id string) error {
    th.mu.Lock()
    defer th.mu.Unlock()

    if _, exists := th.transactions[id]; !exists {
        return errors.New("transaction not found")
    }
    delete(th.transactions, id)
    return th.saveToFile()
}

// saveToFile saves the current state of transactions to a file
func (th *TransactionHistory) saveToFile() error {
    data, err := json.Marshal(th.transactions)
    if err != nil {
        return err
    }
    return os.WriteFile(th.filePath, data, 0644)
}

// loadFromFile loads the transactions from a file
func (th *TransactionHistory) loadFromFile() error {
    file, err := os.ReadFile(th.filePath)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return nil // File does not exist, no transactions to load
        }
        return err
    }
    return json.Unmarshal(file, &th.transactions)
}

// GetTransactionFee calculates the transaction fee using the fee package
func (th *TransactionHistory) GetTransactionFee(transaction Transaction) (float64, error) {
    return fee.Calculate(transaction.Amount)
}

// ValidateTransaction validates a transaction using the validation package
func ValidateTransaction(transaction Transaction) error {
    return validation.Validate(transaction)
}

// EncryptTransaction encrypts a transaction if it's marked as private
func EncryptTransaction(transaction Transaction) (Transaction, error) {
    if !transaction.Private {
        return transaction, nil
    }
    encryptedData, err := crypto.Encrypt(transaction)
    if err != nil {
        return Transaction{}, err
    }
    transaction.From = encryptedData.From
    transaction.To = encryptedData.To
    transaction.Amount = encryptedData.Amount
    transaction.Signature = encryptedData.Signature
    transaction.TransactionFee = encryptedData.TransactionFee
    return transaction, nil
}

// DecryptTransaction decrypts a transaction if it's marked as private
func DecryptTransaction(transaction Transaction) (Transaction, error) {
    if !transaction.Private {
        return transaction, nil
    }
    decryptedData, err := crypto.Decrypt(transaction)
    if err != nil {
        return Transaction{}, err
    }
    transaction.From = decryptedData.From
    transaction.To = decryptedData.To
    transaction.Amount = decryptedData.Amount
    transaction.Signature = decryptedData.Signature
    transaction.TransactionFee = decryptedData.TransactionFee
    return transaction, nil
}
package transaction

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "github.com/synnergy_network/blockchain/transaction/fee"
    "github.com/synnergy_network/crypto"
    "github.com/synnergy_network/crypto/signature"
    "github.com/synnergy_network/utils"
    "github.com/synnergy_network/wallet/authentication"
    "github.com/synnergy_network/wallet/storage"
    "github.com/synnergy_network/wallet/transaction/transaction_types"
    "time"
)

// Transaction represents a blockchain transaction
type Transaction struct {
    ID            string  `json:"id"`
    From          string  `json:"from"`
    To            string  `json:"to"`
    Amount        float64 `json:"amount"`
    Timestamp     int64   `json:"timestamp"`
    Signature     string  `json:"signature"`
    TransactionFee float64 `json:"transaction_fee"`
    IsPrivate     bool    `json:"is_private"`
}

// Validator provides methods for validating transactions
type Validator struct {
    transactionStorage *storage.TransactionStorage
}

// NewValidator initializes and returns a new Validator
func NewValidator(transactionStorage *storage.TransactionStorage) *Validator {
    return &Validator{
        transactionStorage: transactionStorage,
    }
}

// ValidateTransaction validates a transaction
func (v *Validator) ValidateTransaction(tx *Transaction) error {
    // Validate mandatory fields
    if tx.ID == "" || tx.From == "" || tx.To == "" || tx.Amount <= 0 || tx.Timestamp == 0 {
        return errors.New("invalid transaction: missing or invalid fields")
    }

    // Validate the timestamp
    if !v.validateTimestamp(tx.Timestamp) {
        return errors.New("invalid transaction: timestamp out of range")
    }

    // Validate the transaction signature
    if !v.validateSignature(tx) {
        return errors.New("invalid transaction: invalid signature")
    }

    // Validate transaction fee
    if !v.validateTransactionFee(tx) {
        return errors.New("invalid transaction: insufficient transaction fee")
    }

    // Validate balance sufficiency
    if !v.validateBalance(tx) {
        return errors.New("invalid transaction: insufficient balance")
    }

    return nil
}

// validateTimestamp checks if the transaction timestamp is within an acceptable range
func (v *Validator) validateTimestamp(timestamp int64) bool {
    currentTime := time.Now().Unix()
    if timestamp > currentTime || currentTime-timestamp > 3600 {
        return false
    }
    return true
}

// validateSignature verifies the transaction signature
func (v *Validator) validateSignature(tx *Transaction) bool {
    message := tx.From + tx.To + hex.EncodeToString([]byte(string(tx.Amount))) + string(tx.Timestamp)
    messageHash := sha256.Sum256([]byte(message))
    publicKey, err := crypto.DecodePublicKey(tx.From)
    if err != nil {
        return false
    }
    return signature.VerifySignature(publicKey, tx.Signature, messageHash[:])
}

// validateTransactionFee checks if the transaction fee is sufficient
func (v *Validator) validateTransactionFee(tx *Transaction) bool {
    estimatedFee := fee.EstimateTransactionFee(tx)
    return tx.TransactionFee >= estimatedFee
}

// validateBalance checks if the sender has enough balance to cover the transaction
func (v *Validator) validateBalance(tx *Transaction) bool {
    balance, err := v.transactionStorage.GetBalance(tx.From)
    if err != nil {
        return false
    }
    return balance >= tx.Amount+tx.TransactionFee
}
