package transaction

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// RequestCancellation allows a user to request cancellation of a transaction
func (tcm *common.TransactionCancellationManager) RequestTransactionCancellation(txnID string, userID string) error {
	// Verify the transaction exists and belongs to the user
	txn, err := GetTransactionByID(txnID)
	if err != nil || txn.SenderID != userID {
		return errors.New("transaction not found or user not authorized")
	}

	// Check if the cancellation request is within 7 days of the transaction
	if time.Since(txn.Timestamp) > 7*24*time.Hour {
		return errors.New("cancellation request period expired")
	}

	// Freeze the transaction amount
	err = FreezeTransactionAmount(txn)
	if err != nil {
		return err
	}

	// Generate a cancellation request
	cancelRequest := common.CancellationRequest{
		ID:             generateRequestID(txnID),
		TransactionID:  txnID,
		UserID:         userID,
		Timestamp:      time.Now(),
		Status:         "Pending",
		Approvals:      make(map[string]bool),
		Rejections:     make(map[string]bool),
		ApprovalsMutex: sync.Mutex{},
		RejectionsMutex: sync.Mutex{},
	}

	// Broadcast cancellation request to the network
	err = tcm.broadcastCancellationRequest(cancelRequest)
	if err != nil {
		return err
	}

	tcm.Logger.Log("Cancellation request broadcasted successfully:", cancelRequest.ID)
	return nil
}

// HandleCancellationApproval handles approval from nodes for a cancellation request
func (tcm *common.TransactionCancellationManager) HandleTransactionCancellationApproval(requestID string, nodeID string, approval bool) error {
	cancelRequest, err := GetCancellationRequestByID(requestID)
	if err != nil {
		return errors.New("cancellation request not found")
	}

	// Process the approval or rejection
	if approval {
		cancelRequest.ApprovalsMutex.Lock()
		cancelRequest.Approvals[nodeID] = true
		cancelRequest.ApprovalsMutex.Unlock()
	} else {
		cancelRequest.RejectionsMutex.Lock()
		cancelRequest.Rejections[nodeID] = true
		cancelRequest.RejectionsMutex.Unlock()
	}

	// Check if the required number of approvals/rejections has been met
	if tcm.isCancellationApproved(cancelRequest) {
		cancelRequest.Status = "Approved"
		err = tcm.executeCancellation(cancelRequest)
	} else if tcm.isCancellationRejected(cancelRequest) {
		cancelRequest.Status = "Rejected"
		err = tcm.releaseFunds(cancelRequest.TransactionID)
	}

	if err != nil {
		return err
	}

	// Update the ledger
	err = UpdateCancellationRequest(cancelRequest)
	if err != nil {
		return err
	}

	tcm.Logger.Log("Cancellation request handled successfully:", requestID)
	return nil
}

// RequestReversal allows a user to request reversal of a transaction
func (trm *common.TransactionReversalManager) RequestTransactionReversal(txnID string, userID string) error {
	// Verify the transaction exists and belongs to the user
	txn, err := GetTransactionByID(txnID)
	if err != nil || txn.SenderID != userID {
		return errors.New("transaction not found or user not authorized")
	}

	// Check if the reversal request is within 14 days of the transaction
	if time.Since(txn.Timestamp) > 14*24*time.Hour {
		return errors.New("reversal request period expired")
	}

	// Freeze the transaction amount
	err = FreezeTransactionAmount(txn)
	if err != nil {
		return err
	}

	// Generate a reversal request
	reversalRequest := common.ReversalRequest{
		ID:             generateRequestID(txnID),
		TransactionID:  txnID,
		UserID:         userID,
		Timestamp:      time.Now(),
		Status:         "Pending",
		Approvals:      make(map[string]bool),
		Rejections:     make(map[string]bool),
		ApprovalsMutex: sync.Mutex{},
		RejectionsMutex: sync.Mutex{},
	}

	// Broadcast reversal request to the network
	err = trm.broadcastReversalRequest(reversalRequest)
	if err != nil {
		return err
	}

	trm.Logger.Log("Reversal request broadcasted successfully:", reversalRequest.ID)
	return nil
}

// HandleReversalApproval handles approval from nodes for a reversal request
func (trm *common.TransactionReversalManager) HandleTransactionReversalApproval(requestID string, nodeID string, approval bool) error {
	reversalRequest, err := GetReversalRequestByID(requestID)
	if err != nil {
		return errors.New("reversal request not found")
	}

	// Process the approval or rejection
	if approval {
		reversalRequest.ApprovalsMutex.Lock()
		reversalRequest.Approvals[nodeID] = true
		reversalRequest.ApprovalsMutex.Unlock()
	} else {
		reversalRequest.RejectionsMutex.Lock()
		reversalRequest.Rejections[nodeID] = true
		reversalRequest.RejectionsMutex.Unlock()
	}

	// Check if the required number of approvals/rejections has been met
	if trm.isReversalApproved(reversalRequest, txn.Amount) {
		reversalRequest.Status = "Approved"
		err = trm.executeReversal(reversalRequest)
	} else if trm.isReversalRejected(reversalRequest, txn.Amount) {
		reversalRequest.Status = "Rejected"
		err = trm.releaseFunds(reversalRequest.TransactionID)
	}

	if err != nil {
		return err
	}

	// Update the ledger
	err = UpdateReversalRequest(reversalRequest)
	if err != nil {
		return err
	}

	trm.Logger.Log("Reversal request handled successfully:", requestID)
	return nil
}

// ScheduleTransaction schedules a transaction to be executed at a future date
func (tsm *common.TransactionSchedulingManager) ScheduleTransaction(txn common.Transaction, executionTime time.Time) error {
	// Validate the transaction
	err := tsm.Validator.ValidateTransaction(txn)
	if err != nil {
		return errors.New("transaction validation failed")
	}

	// Check if the execution time is in the future
	if executionTime.Before(time.Now()) {
		return errors.New("execution time must be in the future")
	}

	// Create a scheduled transaction
	scheduledTxn := common.ScheduledTransaction{
		ID:            generateTransactionID(txn),
		Transaction:   txn,
		ExecutionTime: executionTime,
		Status:        "Scheduled",
	}

	// Save the scheduled transaction to the ledger
	err = SaveScheduledTransaction(scheduledTxn)
	if err != nil {
		return errors.New("failed to save scheduled transaction")
	}

	// Log the scheduling
	tsm.Logger.Log("Transaction scheduled successfully:", scheduledTxn.ID)
	return nil
}

// ExecuteScheduledTransactions executes transactions that are due for execution
func (tsm *common.TransactionSchedulingManager) ExecuteScheduledTransactions() {
	scheduledTxns, err := GetScheduledTransactionsDue(time.Now())
	if err != nil {
		tsm.Logger.Log("Failed to retrieve scheduled transactions:", err)
		return
	}

	for _, scheduledTxn := range scheduledTxns {
		err := tsm.executeTransaction(scheduledTxn)
		if err != nil {
			tsm.Logger.Log("Failed to execute scheduled transaction:", scheduledTxn.ID, "Error:", err)
		}
	}
}

// CancelScheduledTransaction cancels a scheduled transaction
func (tsm *common.TransactionSchedulingManager) CancelScheduledTransaction(scheduledTxnID string, userID string) error {
	// Retrieve the scheduled transaction
	scheduledTxn, err := GetScheduledTransactionByID(scheduledTxnID)
	if err != nil {
		return errors.New("scheduled transaction not found")
	}

	// Verify the user has permission to cancel the transaction
	if scheduledTxn.Transaction.SenderID != userID {
		return errors.New("user not authorized to cancel this transaction")
	}

	// Update the status to canceled
	scheduledTxn.Status = "Canceled"
	err = UpdateScheduledTransactionStatus(scheduledTxn)
	if err != nil {
		return errors.New("failed to update scheduled transaction status")
	}

	// Log the cancellation
	tsm.Logger.Log("Scheduled transaction canceled successfully:", scheduledTxn.ID)
	return nil
}

// RescheduleTransaction reschedules a transaction to a new execution time
func (tsm *common.TransactionSchedulingManager) RescheduleTransaction(scheduledTxnID string, newExecutionTime time.Time, userID string) error {
	// Retrieve the scheduled transaction
	scheduledTxn, err := GetScheduledTransactionByID(scheduledTxnID)
	if err != nil {
		return errors.New("scheduled transaction not found")
	}

	// Verify the user has permission to reschedule the transaction
	if scheduledTxn.Transaction.SenderID != userID {
		return errors.New("user not authorized to reschedule this transaction")
	}

	// Check if the new execution time is in the future
	if newExecutionTime.Before(time.Now()) {
		return errors.New("new execution time must be in the future")
	}

	// Update the execution time
	scheduledTxn.ExecutionTime = newExecutionTime
	err = UpdateScheduledTransaction(scheduledTxn)
	if err != nil {
		return errors.New("failed to update scheduled transaction")
	}

	// Log the rescheduling
	tsm.Logger.Log("Scheduled transaction rescheduled successfully:", scheduledTxn.ID)
	return nil
}

// Utility functions and helper methods

func (tcm *common.TransactionCancellationManager) BroadcastTransactionCancellationRequest(cancelRequest common.CancellationRequest) error {
	peers, err := DiscoverPeers()
	if err != nil {
		return err
	}

	for _, peer := range peers {
		err := SendMessage(peer, cancelRequest)
		if err != nil {
			tcm.Logger.Log("Failed to send cancellation request to peer:", peer, "Error:", err)
		}
	}

	return nil
}

func (trm *common.TransactionReversalManager) BroadcastTransactionReversalRequest(reversalRequest common.ReversalRequest) error {
	peers, err := DiscoverPeers()
	if err != nil {
		return err
	}

	for _, peer := range peers {
		err := SendMessage(peer, reversalRequest)
		if err != nil {
			trm.Logger.Log("Failed to send reversal request to peer:", peer, "Error:", err)
		}
	}

	return nil
}

func (tcm *common.TransactionCancellationManager) IsTransactionCancellationApproved(cancelRequest common.CancellationRequest) bool {
	requiredApprovals := getRequiredApprovals(len(cancelRequest.Approvals))
	return len(cancelRequest.Approvals) >= requiredApprovals
}

func (tcm *common.TransactionCancellationManager) IsTransactionCancellationRejected(cancelRequest common.CancellationRequest) bool {
	requiredRejections := getRequiredRejections(len(cancelRequest.Rejections))
	return len(cancelRequest.Rejections) >= requiredRejections
}

func (tcm *common.TransactionCancellationManager) ExecuteTransactionCancellation(cancelRequest common.CancellationRequest) error {
	txn, err := GetTransactionByID(cancelRequest.TransactionID)
	if err != nil {
		return errors.New("transaction not found")
	}

	// Revert the transaction
	err = RevertTransaction(txn)
	if err != nil {
		return err
	}

	// Notify the involved parties
	err = tcm.notifyParties(txn, "Transaction has been cancelled.")
	if err != nil {
		return err
	}

	// Update the consensus
	err = tcm.Consensus.Update(txn)
	if err != nil {
		return err
	}

	return nil
}

func (tcm *common.TransactionCancellationManager) ReleaseTransactionCancellationFunds(txnID string) error {
	txn, err := GetTransactionByID(txnID)
	if err != nil {
		return errors.New("transaction not found")
	}

	// Release the frozen amount
	err = ReleaseTransactionAmount(txn)
	if err != nil {
		return err
	}

	// Notify the involved parties
	err = tcm.notifyParties(txn, "Cancellation request rejected. Funds released.")
	if err != nil {
		return err
	}

	return nil
}

func (tcm *common.TransactionCancellationManager) NotifyPartiesOfCancellation(txn common.Transaction, message string) error {
	err := SendNotification(txn.SenderID, message)
	if err != nil {
		return err
	}

	err = SendNotification(txn.ReceiverID, message)
	if err != nil {
		return err
	}

	return nil
}

func (trm *common.TransactionReversalManager) IsTransactionReversalApproved(reversalRequest common.ReversalRequest, amount int) bool {
	requiredApprovals := getRequiredApprovals(amount)
	return len(reversalRequest.Approvals) >= requiredApprovals
}

func (trm *common.TransactionReversalManager) IsTransactionReversalRejected(reversalRequest common.ReversalRequest, amount int) bool {
	requiredRejections := getRequiredRejections(amount)
	return len(reversalRequest.Rejections) >= requiredRejections
}

func (trm *common.TransactionReversalManager) ExecuteTransactionReversal(reversalRequest common.ReversalRequest) error {
	txn, err := common.GetTransactionByID(reversalRequest.TransactionID)
	if err != nil {
		return errors.New("transaction not found")
	}

	// Revert the transaction
	err = RevertTransaction(txn)
	if err != nil {
		return err
	}

	// Notify the involved parties
	err = trm.notifyParties(txn, "Transaction has been reversed.")
	if err != nil {
		return err
	}

	// Update the consensus
	err = trm.Consensus.Update(txn)
	if err != nil {
		return err
	}

	return nil
}

func (trm *common.TransactionReversalManager) ReleaseTransactionReversalFunds(txnID string) error {
	txn, err := GetTransactionByID(txnID)
	if err != nil {
		return errors.New("transaction not found")
	}

	// Release the frozen amount
	err = ReleaseTransactionAmount(txn)
	if err != nil {
		return err
	}

	// Notify the involved parties
	err = trm.notifyParties(txn, "Reversal request rejected. Funds released.")
	if err != nil {
		return err
	}

	return nil
}

func (trm *common.TransactionReversalManager) notifyPartiesOfReversal(txn common.Transaction, message string) error {
	err := SendNotification(txn.SenderID, message)
	if err != nil {
		return err
	}

	err = SendNotification(txn.ReceiverID, message)
	if err != nil {
		return err
	}

	return nil
}

func (tsm *common.TransactionSchedulingManager) ExecuteScheduledTransaction(scheduledTxn common.ScheduledTransaction) error {
	// Execute the transaction
	err := tsm.Consensus.ExecuteTransaction(scheduledTxn.Transaction)
	if err != nil {
		return err
	}

	// Update the status of the scheduled transaction
	scheduledTxn.Status = "Executed"
	err = UpdateScheduledTransactionStatus(scheduledTxn)
	if err != nil {
		return errors.New("failed to update scheduled transaction status")
	}

	// Log the execution
	tsm.Logger.Log("Scheduled transaction executed successfully:", scheduledTxn.ID)
	return nil
}

// generateRequestID generates a unique ID for the cancellation or reversal request
func GenerateTransactionOrCancellationRequestID(txnID string) string {
	data := txnID + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// generateTransactionID generates a unique ID for a transaction
func GenerateTransactionID(txn common.Transaction) string {
	data := txn.ID + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// getRequiredApprovals returns the number of required approvals based on the transaction amount
func GetRequiredApprovalsForCancellationOrReversal(amount int) int {
	switch {
	case amount < 100:
		return 2
	case amount < 10000:
		return 3
	case amount < 100000:
		return 4
	default:
		return 5
	}
}

// getRequiredRejections returns the number of required rejections to deny a cancellation or reversal
func GetRequiredRejectionsForCancellationOrReversal(amount int) int {
	switch {
	case amount < 100:
		return 2
	case amount < 10000:
		return 3
	case amount < 100000:
		return 4
	default:
		return 5
	}
}
