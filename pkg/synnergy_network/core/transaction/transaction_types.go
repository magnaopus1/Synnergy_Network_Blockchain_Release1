package transaction

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)



// NewPrivateTransaction creates a new private transaction
func NewPrivateTransaction(sender, recipient string, amount float64, tokenID, tokenStandard string) (*common.PrivateTransaction, error) {
	timestamp := time.Now()
	tx := &common.PrivateTransaction{
		Sender:        sender,
		Recipient:     recipient,
		Amount:        amount,
		Timestamp:     timestamp,
		TokenID:       tokenID,
		TokenStandard: tokenStandard,
	}
	txHash, err := tx.calculateHash()
	if err != nil {
		return nil, err
	}
	tx.TransactionHash = txHash
	return tx, nil
}

// NewContractSigningTransaction creates a new contract signing transaction.
func NewContractSigningTransaction(sender, receiver, contractData string, priorityFee float64, contractValidity time.Duration) (*common.ContractSigningTransaction, error) {
	txID, err := generateTxID()
	if err != nil {
		return nil, err
	}

	contractHash, err := computeHash(contractData)
	if err != nil {
		return nil, err
	}

	txFee := calculateBaseFee() + calculateVariableFee(contractData) + priorityFee

	return &common.ContractSigningTransaction{
		TxID:             txID,
		Sender:           sender,
		Receiver:         receiver,
		ContractData:     contractData,
		Timestamp:        time.Now(),
		ContractHash:     contractHash,
		TransactionFee:   txFee,
		PriorityFee:      priorityFee,
		ContractValidity: contractValidity,
	}, nil
}

// NewDeployedTokenUsage creates a new DeployedTokenUsage transaction.
func NewDeployedTokenTransaction(sender, receiver string, tokenAmount, fee float64, authFactors []common.AuthFactor, encryptionKey, tokenID, tokenStandard string) *common.DeployedTokenUsage {
	return &common.DeployedTokenUsage{
		TxID:          generateTxID(),
		Sender:        sender,
		Receiver:      receiver,
		TokenAmount:   tokenAmount,
		Fee:           fee,
		Timestamp:     time.Now(),
		AuthFactors:   authFactors,
		EncryptionKey: encryptionKey,
		TokenID:       tokenID,
		TokenStandard: tokenStandard,
	}
}

// NewFeeFreeTokenTransaction creates a new fee-free token transaction.
func NewFeeFreeTokenTransaction(sender, receiver string, amount float64, tokenType, signature string) (*common.FeeFreeTokenTransaction, error) {
	if sender == "" || receiver == "" || amount <= 0 || tokenType == "" || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.FeeFreeTokenTransaction{
		TxID:      txID,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		TokenType: tokenType,
		Timestamp: time.Now(),
		Signature: signature,
		Validated: false,
	}, nil
}

// NewPurchaseTransaction creates a new purchase transaction.
func NewPurchaseTransaction(buyer, seller string, amount float64, tokenType, signature string, contractCalls int, priorityFee float64) (*common.PurchaseTransaction, error) {
	if buyer == "" || seller == "" || amount <= 0 || tokenType == "" || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.PurchaseTransaction{
		TxID:          txID,
		Buyer:         buyer,
		Seller:        seller,
		Amount:        amount,
		TokenType:     tokenType,
		Timestamp:     time.Now(),
		Signature:     signature,
		Validated:     false,
		ContractCalls: contractCalls,
		PriorityFee:   priorityFee,
	}, nil
}

// NewSmartContractTransaction creates a new smart contract transaction.
func NewSmartContractTransaction(sender, contractAddress, functionName string, functionArgs []interface{}, signature string, priorityFee float64, contractComplexity int) (*common.SmartContractTransaction, error) {
	if sender == "" || contractAddress == "" || functionName == "" || signature == "" || contractComplexity <= 0 {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.SmartContractTransaction{
		TxID:              txID,
		Sender:            sender,
		ContractAddress:   contractAddress,
		FunctionName:      functionName,
		FunctionArgs:      functionArgs,
		Timestamp:         time.Now(),
		Signature:         signature,
		Validated:         false,
		PriorityFee:       priorityFee,
		ContractComplexity: contractComplexity,
	}, nil
}

// NewStandardTransaction creates a new standard transaction.
func NewStandardTransaction(sender, receiver string, amount float64, tokenType, signature string, priorityFee float64) (*common.StandardTransaction, error) {
	if sender == "" || receiver == "" || amount <= 0 || tokenType == "" || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.StandardTransaction{
		TxID:        txID,
		Sender:      sender,
		Receiver:    receiver,
		Amount:      amount,
		TokenType:   tokenType,
		Timestamp:   time.Now(),
		Signature:   signature,
		Validated:   false,
		PriorityFee: priorityFee,
	}, nil
}

// NewTokenTransferTransaction creates a new token transfer transaction.
func NewTokenTransferTransaction(sender, receiver string, amount float64, tokenType, signature, transactionType string, priorityFee float64) (*common.TokenTransferTransaction, error) {
	if sender == "" || receiver == "" || amount <= 0 || tokenType == "" || signature == "" || transactionType == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.TokenTransferTransaction{
		TxID:            txID,
		Sender:          sender,
		Receiver:        receiver,
		Amount:          amount,
		TokenType:       tokenType,
		Timestamp:       time.Now(),
		Signature:       signature,
		Validated:       false,
		PriorityFee:     priorityFee,
		TransactionType: transactionType,
	}, nil
}

// NewWalletVerificationTransaction creates a new wallet verification transaction.
func NewWalletVerificationTransaction(walletAddress, verificationType string, securityCheckLevel int, signature string, priorityFee float64) (*common.WalletVerificationTransaction, error) {
	if walletAddress == "" || verificationType == "" || securityCheckLevel <= 0 || signature == "" {
		return nil, errors.New("invalid transaction parameters")
	}

	txID, err := generateUUID()
	if err != nil {
		return nil, err
	}

	return &common.WalletVerificationTransaction{
		TxID:               txID,
		WalletAddress:      walletAddress,
		VerificationType:   verificationType,
		SecurityCheckLevel: securityCheckLevel,
		Timestamp:          time.Now(),
		Signature:          signature,
		Validated:          false,
		PriorityFee:        priorityFee,
	}, nil
}

// NewTransactionFeeEstimator creates a new TransactionFeeEstimator instance.
func NewTransactionFeeEstimator(baseRate, variableRate, priorityRate, congestion float64) *common.TransactionFeeEstimator {
	return &common.TransactionFeeEstimator{
		BaseFeeRate:       baseRate,
		VariableFeeRate:   variableRate,
		PriorityFeeRate:   priorityRate,
		NetworkCongestion: congestion,
	}
}

// Calculate and validate fees, encrypt and decrypt data, generate UUID, calculate hash, and perform validation checks.

func (pt *common.Transaction) calculateHash() (string, error) {
	data := fmt.Sprintf("%s%s%f%s%s%s", pt.Sender, pt.Recipient, pt.Amount, pt.Timestamp.String(), pt.TokenID, pt.TokenStandard)
	hash := sha256.New()
	if _, err := hash.Write([]byte(data)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (pt *common.Transaction) SignTransaction(privateKey string) error {
	signature, err := Sign(pt.TransactionHash, privateKey)
	if err != nil {
		return err
	}
	pt.Signature = signature
	return nil
}

func (pt *common.Transaction) VerifyTransaction(publicKey string) (bool, error) {
	return Verify(pt.TransactionHash, pt.Signature, publicKey)
}

func (pt *common.Transaction) EncryptTransactionData(key string) error {
	data := fmt.Sprintf("%s%s%f%s%s%s", pt.Sender, pt.Recipient, pt.Amount, pt.Timestamp.String(), pt.TokenID, pt.TokenStandard)
	encryptedData, err := EncryptAES(data, key)
	if err != nil {
		return err
	}
	pt.EncryptedData = encryptedData
	return nil
}

func (pt *common.Transaction) DecryptTransactionData(key string) (string, error) {
	decryptedData, err := DecryptAES(pt.EncryptedData, key)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}

func (pt *common.Transaction) validateFee() (float64, error) {
	fee := pt.Amount * 0.01 // 1% fee
	if fee < 0 {
		return 0, errors.New("invalid transaction amount")
	}
	return fee, nil
}

func (pt *common.Transaction) ValidateAndProcessTransaction(publicKey, privateKey string) (bool, error) {
	valid, err := pt.VerifyTransaction(publicKey)
	if !valid || err != nil {
		return false, errors.New("transaction verification failed")
	}

	fee, err := pt.validateFee()
	if err != nil {
		return false, err
	}

	if pt.TokenID == "" || pt.TokenStandard == "" {
		// Handle SYNN transaction
		fmt.Printf("Processing SYNN transaction: Deducting %.2f from %s, crediting %.2f to %s\n", pt.Amount+fee, pt.Sender, pt.Amount, pt.Recipient)
	} else {
		// Handle token transaction
		token, err := GetToken(pt.TokenID, pt.TokenStandard)
		if err != nil {
			return false, err
		}

		senderBalance, err := token.GetBalance(pt.Sender)
		if err != nil || senderBalance < pt.Amount+fee {
			return false, errors.New("insufficient token balance")
		}

		err = token.Transfer(pt.Sender, pt.Recipient, pt.Amount)
		if err != nil {
			return false, err
		}
		fmt.Printf("Processing token transaction: Deducting %.2f %s from %s, crediting %.2f %s to %s\n", pt.Amount+fee, pt.TokenStandard, pt.Sender, pt.Amount, pt.TokenStandard, pt.Recipient)
	}

	return true, nil
}



// generateTxID generates a unique transaction ID
func generateTxID() (string, error) {
	return generateUUID()
}

// calculateBaseFee calculates the base fee for a transaction
func calculateBaseFee() float64 {
	return 0.0000000001 // 
}

// calculateVariableFee calculates the variable fee for a transaction based on its data size
func calculateVariableFee(dataSize string) float64 {
	return float64(len(dataSize)) * 0.00000000001 
}

// generateUUID generates a unique identifier
func generateUUID() (string, error) {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// EstimateFee estimates the transaction fee based on the transaction type and parameters.
func (tfe *common.TransactionFeeEstimator) EstimateFee(txType common.TransactionType, params map[string]interface{}) (float64, error) {
	switch txType {
	case SimpleTransfer:
		return tfe.estimateSimpleTransferFee(params)
	case Purchase:
		return tfe.estimatePurchaseFee(params)
	case DeployedTokenUsage:
		return tfe.estimateDeployedTokenUsageFee(params)
	case ContractSigning:
		return tfe.estimateContractSigningFee(params)
	case WalletVerification:
		return tfe.estimateWalletVerificationFee(params)
	default:
		return 0, errors.New("unsupported transaction type")
	}
}

func (tfe *common.TransactionFeeEstimator) EstimateSimpleTransferFee(params map[string]interface{}) (float64, error) {
	dataSize, ok := params["dataSize"].(int)
	if !ok {
		return 0, errors.New("invalid parameters for simple transfer")
	}

	baseFee := tfe.BaseFeeRate
	variableFee := float64(dataSize) * tfe.VariableFeeRate
	priorityFee := 0.0
	if priority, ok := params["priority"].(bool); ok && priority {
		priorityFee = tfe.PriorityFeeRate
	}

	totalFee := baseFee + variableFee + priorityFee
	return totalFee, nil
}

func (tfe *common.TransactionFeeEstimator) EstimatePurchaseFee(params map[string]interface{}) (float64, error) {
	contractCalls, ok := params["contractCalls"].(int)
	if !ok {
		return 0, errors.New("invalid parameters for purchase")
	}

	baseFee := tfe.BaseFeeRate * 2 // Medium complexity base fee
	variableFee := float64(contractCalls) * tfe.VariableFeeRate
	priorityFee := 0.0
	if priority, ok := params["priority"].(bool); ok && priority {
		priorityFee = tfe.PriorityFeeRate
	}

	totalFee := baseFee + variableFee + priorityFee
	return totalFee, nil
}

func (tfe *common.TransactionFeeEstimator) EstimateDeployedTokenUsageFee(params map[string]interface{}) (float64, error) {
	computationUnits, ok := params["computationUnits"].(int)
	if !ok {
		return 0, errors.New("invalid parameters for deployed token usage")
	}

	baseFee := tfe.BaseFeeRate * 2 // Medium complexity base fee
	variableFee := float64(computationUnits) * tfe.VariableFeeRate
	priorityFee := 0.0
	if priority, ok := params["priority"].(bool); ok && priority {
		priorityFee = tfe.PriorityFeeRate
	}

	totalFee := baseFee + variableFee + priorityFee
	return totalFee, nil
}

func (tfe *common.TransactionFeeEstimator) EstimateContractSigningFee(params map[string]interface{}) (float64, error) {
	complexityFactor, ok := params["complexityFactor"].(int)
	if !ok {
		return 0, errors.New("invalid parameters for contract signing")
	}

	baseFee := tfe.BaseFeeRate * 4 // High complexity base fee
	variableFee := float64(complexityFactor) * tfe.VariableFeeRate
	priorityFee := 0.0
	if priority, ok := params["priority"].(bool); ok && priority {
		priorityFee = tfe.PriorityFeeRate
	}

	totalFee := baseFee + variableFee + priorityFee
	return totalFee, nil
}

func (tfe *common.TransactionFeeEstimator) EstimateWalletVerificationFee(params map[string]interface{}) (float64, error) {
	securityCheckLevel, ok := params["securityCheckLevel"].(int)
	if !ok {
		return 0, errors.New("invalid parameters for wallet verification")
	}

	baseFee := tfe.BaseFeeRate // Low to medium base fee depending on complexity
	variableFee := float64(securityCheckLevel) * tfe.VariableFeeRate
	priorityFee := 0.0
	if priority, ok := params["priority"].(bool); ok && priority {
		priorityFee = tfe.PriorityFeeRate
	}

	totalFee := baseFee + variableFee + priorityFee
	return totalFee, nil
}

func (tfe *common.TransactionFeeEstimator) AdjustTransactionFeeForNetworkCongestion(fee float64) float64 {
	return fee * (1 + tfe.NetworkCongestion)
}

// SignTransaction signs the contract signing transaction.
func (tx *common.ContractSigningTransaction) SignContractSigningTransaction(privateKey string) error {
	signature, err := Sign(tx.ContractHash, privateKey)
	if err != nil {
		return err
	}
	tx.Signature = signature
	return nil
}

// ValidateTransaction validates the contract signing transaction.
func (tx *common.ContractSigningTransaction) ValidateContractSigningTransaction() error {
	// Validate transaction ID
	if !validateTxID(tx.TxID) {
		return errors.New("invalid transaction ID")
	}

	// Validate sender and receiver
	if !validateAddress(tx.Sender) || !validateAddress(tx.Receiver) {
		return errors.New("invalid sender or receiver address")
	}

	// Validate contract hash
	if !validateHash(tx.ContractHash) {
		return errors.New("invalid contract hash")
	}

	// Validate signature
	if !validateSignature(tx.ContractHash, tx.Signature, tx.Sender) {
		return errors.New("invalid transaction signature")
	}

	// Validate transaction fee
	if tx.TransactionFee < calculateBaseFee() {
		return errors.New("transaction fee is too low")
	}

	// Validate contract data integrity
	if hash, err := computeHash(tx.ContractData); err != nil || hash != tx.ContractHash {
		return errors.New("contract data integrity validation failed")
	}

	return nil
}

// ExecuteTransaction executes the contract signing transaction.
func (tx *common.ContractSigningTransaction) ExecuteContractSigningTransaction() error {
	// Verify sender identity
	if err := verifyUser(tx.Sender); err != nil {
		return err
	}

	// Deduct transaction fee
	if err := deductFee(tx.Sender, tx.TransactionFee); err != nil {
		return err
	}

	// Store contract data
	if err := storeData(tx.ContractData, tx.ContractHash); err != nil {
		return err
	}

	// Broadcast transaction to the network
	if err := broadcastTransaction(tx); err != nil {
		return err
	}

	return nil
}

// ValidateContract checks the validity of the contract.
func (tx *common.ContractSigningTransaction) ValidateContract() error {
	// Validate contract validity period
	if time.Since(tx.Timestamp) > tx.ContractValidity {
		return errors.New("contract has expired")
	}

	// Validate contract data
	if !validateContractData(tx.ContractData) {
		return errors.New("invalid contract data")
	}

	return nil
}

// EncryptContractData encrypts the contract data.
func (tx *common.ContractSigningTransaction) EncryptContractData(key string) (string, error) {
	encryptedData, err := encryptData(tx.ContractData, key)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptContractData decrypts the contract data.
func (tx *common.ContractSigningTransaction) DecryptContractData(encryptedData, key string) (string, error) {
	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}

// ValidateTransaction validates the DeployedTokenUsage transaction.
func (dt *common.DeployedTokenUsage) ValidateDeployedTokenUsageTransaction() error {
	// Verify identities
	if err := verifyUser(dt.Sender); err != nil {
		return fmt.Errorf("sender verification failed: %w", err)
	}
	if err := verifyUser(dt.Receiver); err != nil {
		return fmt.Errorf("receiver verification failed: %w", err)
	}

	// Validate the token amount and fee
	if dt.TokenAmount <= 0 {
		return errors.New("invalid token amount")
	}
	if dt.Fee < 0 {
		return errors.New("invalid transaction fee")
	}

	// Validate authentication factors
	mfa := newMultiFactorValidation(dt.Sender, dt.AuthFactors, 2)
	if !mfa.validateAllFactors() {
		return errors.New("multi-factor authentication failed")
	}

	// Validate the transaction signature
	if !validateSignature(dt.Sender, dt.Signature, dt.TxID) {
		return errors.New("invalid transaction signature")
	}

	return nil
}

// EncryptTransactionData encrypts the transaction data.
func (dt *common.DeployedTokenUsage) EncryptDeployedTokenUsageTransactionData() error {
	encryptedData, err := encryptData(fmt.Sprintf("%s:%f:%s:%f:%s:%s", dt.Sender, dt.TokenAmount, dt.Receiver, dt.Fee, dt.TokenID, dt.TokenStandard), dt.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction data: %w", err)
	}
	dt.TxID = encryptedData
	return nil
}

// DecryptTransactionData decrypts the transaction data.
func (dt *common.DeployedTokenUsage) DecryptDeployedTokenUsageTransactionData() error {
	decryptedData, err := decryptData(dt.TxID, dt.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt transaction data: %w", err)
	}
	parts := strings.Split(decryptedData, ":")
	if len(parts) != 6 {
		return errors.New("invalid decrypted data format")
	}
	dt.Sender = parts[0]
	dt.TokenAmount, _ = strconv.ParseFloat(parts[1], 64)
	dt.Receiver = parts[2]
	dt.Fee, _ = strconv.ParseFloat(parts[3], 64)
	dt.TokenID = parts[4]
	dt.TokenStandard = parts[5]
	return nil
}

// ExecuteTransaction executes the DeployedTokenUsage transaction.
func (dt *common.DeployedTokenUsage) ExecuteDeployedTokenUsageTransaction() error {
	// Validate the transaction
	if err := dt.ValidateTransaction(); err != nil {
		return err
	}

	// Encrypt transaction data
	if err := dt.EncryptTransactionData(); err != nil {
		return err
	}

	// Execute consensus algorithm
	if err := executeConsensus(dt.TxID); err != nil {
		return fmt.Errorf("consensus execution failed: %w", err)
	}

	// Decrypt transaction data for processing
	if err := dt.DecryptTransactionData(); err != nil {
		return err
	}

	if dt.TokenID == "" || dt.TokenStandard == "" {
		// Handle SYNN transaction
		fmt.Printf("Processing SYNN transaction: Deducting %.2f from %s, crediting %.2f to %s\n", dt.TokenAmount+dt.Fee, dt.Sender, dt.TokenAmount, dt.Receiver)
	} else {
		// Handle token transaction
		token, err := GetToken(dt.TokenID, dt.TokenStandard)
		if err != nil {
			return err
		}

		senderBalance, err := token.GetBalance(dt.Sender)
		if err != nil || senderBalance < dt.TokenAmount+dt.Fee {
			return errors.New("insufficient token balance")
		}

		err = token.Transfer(dt.Sender, dt.Receiver, dt.TokenAmount)
		if err != nil {
			return err
		}
		fmt.Printf("Processing token transaction: Deducting %.2f %s from %s, crediting %.2f %s to %s\n", dt.TokenAmount+dt.Fee, dt.TokenStandard, dt.Sender, dt.TokenAmount, dt.TokenStandard, dt.Receiver)
	}

	return nil
}

// Validate validates the fee-free token transaction.
func (t *common.FeeFreeTokenTransaction) ValidateFeeLessTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.Sender, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Check if the token type is eligible for fee-free transactions
	if !isFeeFreeToken(t.TokenType) {
		return errors.New("token type not eligible for fee-free transactions")
	}

	// Compliance checks
	err = checkCompliance(t.Sender, t.Receiver, t.Amount)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the fee-free token transaction.
func (t *common.FeeFreeTokenTransaction) ExecuteFeeLessTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Ensure the sender has sufficient balance
	balance, err := getTokenBalance(t.Sender, t.TokenType)
	if err != nil {
		return err
	}
	if balance < t.Amount {
		return errors.New("insufficient balance")
	}

	// Perform the token transfer
	err = transferTokens(t.Sender, t.Receiver, t.Amount, t.TokenType)
	if err != nil {
		return err
	}

	// Log the transaction
	logTransaction(t.TxID, t.Sender, t.Receiver, t.Amount, t.TokenType, t.Timestamp)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.FeeFreeTokenTransaction) GetFeeLessTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":      t.TxID,
		"Sender":    t.Sender,
		"Receiver":  t.Receiver,
		"Amount":    t.Amount,
		"TokenType": t.TokenType,
		"Timestamp": t.Timestamp,
		"Validated": t.Validated,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.FeeFreeTokenTransaction) EncryptFeeLessTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.FeeFreeTokenTransaction) DecryptFeeLessTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Validate validates the purchase transaction.
func (t *common.PurchaseTransaction) ValidatePurchaseTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.Buyer, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Check if the token type is valid
	if !isValidTokenType(t.TokenType) {
		return errors.New("invalid token type")
	}

	// Compliance checks
	err = checkCompliance(t.Buyer, t.Seller, t.Amount)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the purchase transaction.
func (t *common.PurchaseTransaction) ExecutePurchaseTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Ensure the buyer has sufficient balance
	balance, err := getTokenBalance(t.Buyer, t.TokenType)
	if err != nil {
		return err
	}
	if balance < t.Amount {
		return errors.New("insufficient balance")
	}

	// Perform the token transfer
	err = transferTokens(t.Buyer, t.Seller, t.Amount, t.TokenType)
	if err != nil {
		return err
	}

	// Calculate fees
	baseFee := calculateBaseFee()
	variableFee := calculateVariableFee(t.ContractCalls)
	totalFee := baseFee + variableFee + t.PriorityFee

	// Deduct fees from buyer's balance
	err = deductFee(t.Buyer, totalFee)
	if err != nil {
		return err
	}

	// Log the transaction
	logTransaction(t.TxID, t.Buyer, t.Seller, t.Amount, t.TokenType, t.Timestamp, totalFee)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.PurchaseTransaction) GetPurchaseTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":          t.TxID,
		"Buyer":         t.Buyer,
		"Seller":        t.Seller,
		"Amount":        t.Amount,
		"TokenType":     t.TokenType,
		"Timestamp":     t.Timestamp,
		"Validated":     t.Validated,
		"ContractCalls": t.ContractCalls,
		"PriorityFee":   t.PriorityFee,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.PurchaseTransaction) EncryptPurchaseTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.PurchaseTransaction) DecryptPurchaseTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Validate validates the smart contract transaction.
func (t *common.SmartContractTransaction) ValidateSmartContractTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.Sender, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Validate contract address and function name
	if !isValidContractAddress(t.ContractAddress) || !isValidFunctionName(t.FunctionName) {
		return errors.New("invalid contract address or function name")
	}

	// Compliance checks
	err = checkCompliance(t.Sender, t.ContractAddress, t.FunctionArgs)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the smart contract transaction.
func (t *common.SmartContractTransaction) ExecuteSmartContractTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Ensure the sender has sufficient balance
	balance, err := getTokenBalance(t.Sender, "Synthron")
	if err != nil {
		return err
	}
	if balance < t.PriorityFee {
		return errors.New("insufficient balance")
	}

	// Perform the smart contract function call
	err = callSmartContractFunction(t.Sender, t.ContractAddress, t.FunctionName, t.FunctionArgs)
	if err != nil {
		return err
	}

	// Calculate fees
	baseFee := calculateBaseFee()
	variableFee := calculateVariableFee(t.ContractComplexity)
	totalFee := baseFee + variableFee + t.PriorityFee

	// Deduct fees from sender's balance
	err = deductFee(t.Sender, totalFee)
	if err != nil {
		return err
	}

	// Log the transaction
	logTransaction(t.TxID, t.Sender, t.ContractAddress, t.FunctionName, t.FunctionArgs, t.Timestamp, totalFee)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.SmartContractTransaction) GetSmartContractTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":              t.TxID,
		"Sender":            t.Sender,
		"ContractAddress":   t.ContractAddress,
		"FunctionName":      t.FunctionName,
		"FunctionArgs":      t.FunctionArgs,
		"Timestamp":         t.Timestamp,
		"Validated":         t.Validated,
		"PriorityFee":       t.PriorityFee,
		"ContractComplexity": t.ContractComplexity,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.SmartContractTransaction) EncryptSmartContractTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.SmartContractTransaction) DecryptSmartContractTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Validate validates the standard transaction.
func (t *common.StandardTransaction) ValidateStandardTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.Sender, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Check if the token type is valid
	if !isValidTokenType(t.TokenType) {
		return errors.New("invalid token type")
	}

	// Compliance checks
	err = checkCompliance(t.Sender, t.Receiver, t.Amount)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the standard transaction.
func (t *common.StandardTransaction) ExecuteStandardTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Ensure the sender has sufficient balance
	balance, err := getTokenBalance(t.Sender, t.TokenType)
	if err != nil {
		return err
	}
	if balance < t.Amount {
		return errors.New("insufficient balance")
	}

	// Perform the token transfer
	err = transferTokens(t.Sender, t.Receiver, t.Amount, t.TokenType)
	if err != nil {
		return err
	}

	// Calculate fees
	baseFee := calculateBaseFee()
	variableFee := calculateVariableFee(1) // Standard transaction complexity
	totalFee := baseFee + variableFee + t.PriorityFee

	// Deduct fees from sender's balance
	err = deductFee(t.Sender, totalFee)
	if err != nil {
		return err
	}

	// Log the transaction
	logTransaction(t.TxID, t.Sender, t.Receiver, t.Amount, t.TokenType, t.Timestamp, totalFee)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.StandardTransaction) GetStandardTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":        t.TxID,
		"Sender":      t.Sender,
		"Receiver":    t.Receiver,
		"Amount":      t.Amount,
		"TokenType":   t.TokenType,
		"Timestamp":   t.Timestamp,
		"Validated":   t.Validated,
		"PriorityFee": t.PriorityFee,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.StandardTransaction) EncryptStandardTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.StandardTransaction) DecryptStandardTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Validate validates the token transfer transaction.
func (t *common.TokenTransferTransaction) ValidateTokenTransferTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.Sender, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Check if the token type is valid
	if !isValidTokenType(t.TokenType) {
		return errors.New("invalid token type")
	}

	// Compliance checks
	err = checkCompliance(t.Sender, t.Receiver, t.Amount)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the token transfer transaction.
func (t *common.TokenTransferTransaction) ExecuteTokenTransferTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Ensure the sender has sufficient balance
	balance, err := getTokenBalance(t.Sender, t.TokenType)
	if err != nil {
		return err
	}
	if balance < t.Amount {
		return errors.New("insufficient balance")
	}

	// Perform the token transfer
	err = transferTokens(t.Sender, t.Receiver, t.Amount, t.TokenType)
	if err != nil {
		return err
	}

	// Calculate fees
	baseFee := calculateBaseFee()
	variableFee := calculateVariableFee(1) // Standard transaction complexity
	totalFee := baseFee + variableFee + t.PriorityFee

	// Deduct fees from sender's balance
	err = deductFee(t.Sender, totalFee)
	if err != nil {
		return err
	}

	// Log the transaction
	logTransaction(t.TxID, t.Sender, t.Receiver, t.Amount, t.TokenType, t.Timestamp, totalFee)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.TokenTransferTransaction) GetTokenTransferTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":            t.TxID,
		"Sender":          t.Sender,
		"Receiver":        t.Receiver,
		"Amount":          t.Amount,
		"TokenType":       t.TokenType,
		"Timestamp":       t.Timestamp,
		"Validated":       t.Validated,
		"PriorityFee":     t.PriorityFee,
		"TransactionType": t.TransactionType,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.TokenTransferTransaction) EncryptTokenTransferTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.TokenTransferTransaction) DecryptTokenTransferTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// Validate validates the wallet verification transaction.
func (t *common.WalletVerificationTransaction) ValidateWalletVerificationTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Validated {
		return errors.New("transaction already validated")
	}

	// Verify the transaction signature
	valid, err := Verify(t.WalletAddress, t.Signature, t.TxID)
	if err != nil || !valid {
		return errors.New("invalid transaction signature")
	}

	// Compliance checks
	err = checkCompliance(t.WalletAddress, "", 0)
	if err != nil {
		return err
	}

	t.Validated = true
	return nil
}

// Execute executes the wallet verification transaction.
func (t *common.WalletVerificationTransaction) ExecuteWalletVerfiicationTransaction() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.Validated {
		return errors.New("transaction not validated")
	}

	// Perform the security checks
	err := performSecurityChecks(t.WalletAddress, t.SecurityCheckLevel)
	if err != nil {
		return err
	}

	// Calculate fees
	baseFee := calculateBaseFee()
	variableFee := calculateVariableFee(t.SecurityCheckLevel)
	totalFee := baseFee + variableFee + t.PriorityFee

	// Log the transaction
	logTransaction(t.TxID, t.WalletAddress, "", 0, "", t.Timestamp, totalFee)

	// Record the transaction in the blockchain
	err = recordTransaction(t)
	if err != nil {
		return err
	}

	return nil
}

// GetTransactionDetails returns the details of the transaction.
func (t *common.WalletVerificationTransaction) GetWalletVerificationTransactionDetails() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	return map[string]interface{}{
		"TxID":               t.TxID,
		"WalletAddress":      t.WalletAddress,
		"VerificationType":   t.VerificationType,
		"SecurityCheckLevel": t.SecurityCheckLevel,
		"Timestamp":          t.Timestamp,
		"Validated":          t.Validated,
		"PriorityFee":        t.PriorityFee,
	}
}

// EncryptTransactionData encrypts the transaction data.
func (t *common.WalletVerificationTransaction) EncryptWalletVerificationTransactionData(key []byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.GetTransactionDetails()
	encryptedData, err := encryptData(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptTransactionData decrypts the transaction data.
func (t *common.WalletVerificationTransaction) DecryptWalletVerificationTransactionData(encryptedData string, key []byte) (map[string]interface{}, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decryptedData, err := decryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}


