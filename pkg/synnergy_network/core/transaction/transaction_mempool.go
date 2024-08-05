package transaction

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)



func (th common.TransactionHeap) LenTransactionHeap() int { return len(th) }

func (th common.TransactionHeap) LessTransactionHeap(i, j int) bool {
	// Higher fee transactions get higher priority, if fees are equal, older transactions get higher priority
	if th[i].Fee == th[j].Fee {
		return th[i].Timestamp.Before(th[j].Timestamp)
	}
	return th[i].Fee > th[j].Fee
}
func (th common.TransactionHeap) SwapTransactionHeap(i, j int) { th[i], th[j] = th[j], th[i] }
func (th *common.TransactionHeap) PushTransactionHeap(x interface{}) {
	*th = append(*th, x.(*common.Transaction))
}
func (th *common.TransactionHeap) PopTransactionHeap() interface{} {
	old := *th
	n := len(old)
	item := old[n-1]
	*th = old[0 : n-1]
	return item
}


// ValidateTransaction validates if a transaction can be processed as a fee-less transfer.
func (v *common.FeeLessTransferValidator) ValidateWhetherTransactionCanBeFeeLessTransfer(tx common.Transaction) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if the asset is eligible for fee-less transfer
	if !v.validAssets[tx.AssetID] {
		return errors.New("asset not eligible for fee-less transfer")
	}

	// Check if the user is eligible for fee-less transfer
	if !v.userEligibility[tx.UserID] {
		return errors.New("user not eligible for fee-less transfer")
	}

	// Check transfer limits
	if limit, ok := v.transferLimits[tx.UserID]; ok && tx.Amount > limit {
		return errors.New("transfer amount exceeds the limit for fee-less transfer")
	}

	// Validate transaction signatures
	if err := v.validateSignatures(tx); err != nil {
		return err
	}

	// All checks passed
	return nil
}

// validateSignatures validates the signatures of the transaction.
func (v *common.FeeLessTransferValidator) ValidateTransactionSignatures(tx common.Transaction) error {
	signatureCount := 0
	for _, signer := range v.authorizedSigners {
		if v.signatureValidator.Validate(tx.Signature, signer) {
			signatureCount++
		}
	}
	if signatureCount < len(v.authorizedSigners)/2+1 {
		return errors.New("insufficient signatures for fee-less transfer")
	}
	return nil
}

// SetUserEligibility sets the eligibility of a user for fee-less transfers.
func (v *common.FeeLessTransferValidator) SetUserEligibilityForFeeLessTransfers(userID string, eligible bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.userEligibility[userID] = eligible
}

// SetTransferLimit sets the transfer limit for a user.
func (v *common.FeeLessTransferValidator) SetUserFeeLessTransferLimit(userID string, limit int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.transferLimits[userID] = limit
}

// AddAuthorizedSigner adds a new authorized signer.
func (v *common.FeeLessTransferValidator) AddAuthorizedSignerTooFeeLessTransfer(signer string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.authorizedSigners = append(v.authorizedSigners, signer)
}

// VerifySignature is a stub function to simulate signature verification
func VerifyTransactionSignature(tx *common.Transaction) bool {
	// Simulate signature verification
	return true
}


// AddTransaction adds a transaction to the mempool if it passes validation.
func (mp *common.Mempool) AddValidatedTransactionToMempool(tx *common.Transaction) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	// Validate transaction
	if err := mp.validateTransaction(tx); err != nil {
		return err
	}

	// Add to heap and map
	if len(mp.transactions) >= mp.maxSize {
		// Remove the lowest priority transaction if mempool is full
		lowest := heap.Pop(mp.txHeap).(*common.Transaction)
		delete(mp.transactions, lowest.ID)
	}
	heap.Push(mp.txHeap, tx)
	mp.transactions[tx.ID] = tx

	return nil
}

// validateTransaction checks if a transaction is valid.
func (mp *common.Mempool) ValidateTransaction(tx *common.Transaction) error {
	// Check signature
	if !verifySignature(tx) {
		return errors.New("invalid transaction signature")
	}

	// Check for duplicate
	if _, exists := mp.transactions[tx.ID]; exists {
		return errors.New("duplicate transaction")
	}

	// Validate fee-less transfer
	if tx.Fee == 0 {
		if err := mp.validator.ValidateTransaction(*tx); err != nil {
			return err
		}
	}

	// Additional checks can be added here (e.g., fee validation, balance checks)
	// ...

	return nil
}

// GetTransaction retrieves a transaction from the mempool.
func (mp *common.Mempool) GetTransactionFromMempool(txID string) (*common.Transaction, bool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	tx, exists := mp.transactions[txID]
	return tx, exists
}

// RemoveTransaction removes a transaction from the mempool.
func (mp *common.Mempool) RemoveTransactionFromMempool(txID string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if tx, exists := mp.transactions[txID]; exists {
		// Remove from map and heap
		delete(mp.transactions, txID)
		for i, t := range *mp.txHeap {
			if t.ID == txID {
				heap.Remove(mp.txHeap, i)
				break
			}
		}
	}
}

// Optimize periodically optimizes the mempool by removing stale transactions and prioritizing high-fee transactions.
func (mp *common.Mempool) OptimizeMempoolPeriodically() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	now := time.Now()
	staleThreshold := now.Add(-30 * time.Minute)

	// Remove stale transactions
	for _, tx := range mp.transactions {
		if tx.Timestamp.Before(staleThreshold) {
			delete(mp.transactions, tx.ID)
		}
	}

	// Rebuild heap to ensure priority queue is correct
	*mp.txHeap = (*mp.txHeap)[:0]
	for _, tx := range mp.transactions {
		heap.Push(mp.txHeap, tx)
	}
}

// StartOptimizationRoutine starts a routine to optimize the mempool at regular intervals.
func (mp *common.Mempool) StartMempoolOptimizationRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				mp.Optimize()
			}
		}
	}()
}

// MonitorTransactions monitors transactions for compliance and fraud detection.
func (mp *common.Mempool) MonitorMempoolTransactionsForComplianceAndFraud() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	for _, tx := range mp.transactions {
		// Compliance checks
		if err := checkCompliance(tx); err != nil {
			mp.RemoveTransaction(tx.ID)
		}

		// Fraud detection
		if detectFraud(tx) {
			mp.RemoveTransaction(tx.ID)
		}
	}
}

// StartMonitoringRoutine starts a routine to monitor transactions for compliance and fraud detection.
func (mp *common.Mempool) StartMonitoringMempoolRoutineForComplianceAndFraud(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				mp.MonitorTransactions()
			}
		}
	}()
}

// checkCompliance is a stub function to simulate compliance checks
func CheckTransactionCompliance(tx *common.Transaction) error {
	// Simulate compliance check
	return nil
}

// detectFraud is a stub function to simulate fraud detection
func DetectTransactionFraud(tx *common.Transaction) bool {
	// Simulate fraud detection
	return false
}
