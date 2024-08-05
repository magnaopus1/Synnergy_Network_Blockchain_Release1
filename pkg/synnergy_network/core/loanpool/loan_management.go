package loan_management

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/utils"
)


// NewLoanCore initializes a new LoanCore instance.
func NewLoanCore() *LoanCore {
	return &LoanCore{
		loans: make(map[string]Loan),
	}
}

// CreateLoan creates a new loan.
func (lc *LoanCore) CreateLoan(borrowerID string, amount float64, interestRate float64, durationMonths int, collateral Collateral) (string, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loanID := utils.GenerateUUID()
	startDate := time.Now()
	endDate := startDate.AddDate(0, durationMonths, 0)

	loan := Loan{
		ID:            loanID,
		BorrowerID:    borrowerID,
		Amount:        amount,
		InterestRate:  interestRate,
		StartDate:     startDate,
		EndDate:       endDate,
		Status:        "Active",
		Collateral:    collateral,
		RepaymentPlan: lc.calculateRepaymentPlan(amount, interestRate, durationMonths),
	}

	lc.loans[loanID] = loan
	return loanID, nil
}

// GetLoan retrieves a loan by its ID.
func (lc *LoanCore) GetLoan(loanID string) (Loan, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return Loan{}, errors.New("loan not found")
	}

	return loan, nil
}

// ListLoans lists all loans.
func (lc *LoanCore) ListLoans() []Loan {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	var loans []Loan
	for _, loan := range lc.loans {
		loans = append(loans, loan)
	}

	return loans
}

// RepayLoan handles repayment of a loan.
func (lc *LoanCore) RepayLoan(loanID string, amount float64) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	if loan.Status != "Active" {
		return errors.New("loan is not active")
	}

	repayment := Repayment{
		Date:   time.Now(),
		Amount: amount,
	}
	loan.RepaymentPlan = append(loan.RepaymentPlan, repayment)

	remainingAmount := lc.calculateRemainingAmount(loan)
	if remainingAmount <= 0 {
		loan.Status = "Repaid"
	}

	lc.loans[loanID] = loan
	return nil
}

// DefaultLoan handles loan default.
func (lc *LoanCore) DefaultLoan(loanID string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	loan.Status = "Defaulted"
	lc.loans[loanID] = loan
	return nil
}

// calculateRepaymentPlan calculates the repayment plan for a loan.
func (lc *LoanCore) calculateRepaymentPlan(amount float64, interestRate float64, durationMonths int) []Repayment {
	var plan []Repayment
	monthlyPayment := (amount * interestRate / 12) / (1 - (1 / (1 + interestRate/12) / (12 * float64(durationMonths))))

	for i := 0; i < durationMonths; i++ {
		plan = append(plan, Repayment{
			Date:   time.Now().AddDate(0, i+1, 0),
			Amount: monthlyPayment,
		})
	}

	return plan
}

// calculateRemainingAmount calculates the remaining amount for a loan.
func (lc *LoanCore) calculateRemainingAmount(loan Loan) float64 {
	paidAmount := 0.0
	for _, repayment := range loan.RepaymentPlan {
		paidAmount += repayment.Amount
	}
	totalAmount := loan.Amount + (loan.Amount * loan.InterestRate / 100)
	return totalAmount - paidAmount
}

// UpdateCollateral updates the collateral for a loan.
func (lc *LoanCore) UpdateCollateral(loanID string, newCollateral Collateral) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	loan.Collateral = newCollateral
	lc.loans[loanID] = loan
	return nil
}

// CloseLoan closes a loan manually.
func (lc *LoanCore) CloseLoan(loanID string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	loan.Status = "Closed"
	lc.loans[loanID] = loan
	return nil
}

// LiquidateCollateral liquidates the collateral for a defaulted loan.
func (lc *LoanCore) LiquidateCollateral(loanID string) (float64, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	loan, exists := lc.loans[loanID]
	if !exists {
		return 0, errors.New("loan not found")
	}

	if loan.Status != "Defaulted" {
		return 0, errors.New("loan is not in default status")
	}

	// Logic to liquidate collateral and recover funds
	liquidatedValue := loan.Collateral.Value
	loan.Status = "Liquidated"
	lc.loans[loanID] = loan

	return liquidatedValue, nil
}

// NewLoanDisbursement initializes a new LoanDisbursement instance.
func NewLoanDisbursement() *LoanDisbursement {
	return &LoanDisbursement{
		Disbursements: make(map[string]Disbursement),
	}
}

// CreateDisbursement creates a new loan disbursement.
func (ld *LoanDisbursement) CreateDisbursement(loanID, borrowerID string, amount float64) (string, error) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	disbursementID := utils.GenerateUUID()
	disbursement := Disbursement{
		ID:         disbursementID,
		LoanID:     loanID,
		BorrowerID: borrowerID,
		Amount:     amount,
		Status:     "Pending",
		CreatedAt:  time.Now(),
	}

	ld.Disbursements[disbursementID] = disbursement
	return disbursementID, nil
}

// ProcessDisbursement processes the loan disbursement.
func (ld *LoanDisbursement) ProcessDisbursement(disbursementID string) error {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	disbursement, exists := ld.Disbursements[disbursementID]
	if !exists {
		return errors.New("disbursement not found")
	}

	if disbursement.Status != "Pending" {
		return errors.New("disbursement is not in a pending state")
	}

	// Encrypt the disbursement details for security
	encryptedAmount, err := security.Encrypt(fmt.Sprintf("%f", disbursement.Amount))
	if err != nil {
		return fmt.Errorf("failed to encrypt disbursement amount: %v", err)
	}

	// Simulate processing the disbursement
	disbursement.Status = "Processed"
	disbursement.ProcessedAt = time.Now()

	// Update the disbursement record with the encrypted amount
	disbursement.Amount, err = strconv.ParseFloat(encryptedAmount, 64)
	if err != nil {
		return fmt.Errorf("failed to parse encrypted amount: %v", err)
	}

	ld.Disbursements[disbursementID] = disbursement
	return nil
}

// GetDisbursement retrieves a disbursement by its ID.
func (ld *LoanDisbursement) GetDisbursement(disbursementID string) (Disbursement, error) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	disbursement, exists := ld.Disbursements[disbursementID]
	if !exists {
		return Disbursement{}, errors.New("disbursement not found")
	}

	return disbursement, nil
}

// ListDisbursements lists all disbursements.
func (ld *LoanDisbursement) ListDisbursements() []Disbursement {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	var disbursements []Disbursement
	for _, disbursement := range ld.Disbursements {
		disbursements = append(disbursements, disbursement)
	}

	return disbursements
}

// CancelDisbursement cancels a pending disbursement.
func (ld *LoanDisbursement) CancelDisbursement(disbursementID string) error {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	disbursement, exists := ld.Disbursements[disbursementID]
	if !exists {
		return errors.New("disbursement not found")
	}

	if disbursement.Status != "Pending" {
		return errors.New("only pending disbursements can be cancelled")
	}

	disbursement.Status = "Cancelled"
	ld.Disbursements[disbursementID] = disbursement
	return nil
}

// CompleteDisbursement completes a processed disbursement.
func (ld *LoanDisbursement) CompleteDisbursement(disbursementID string) error {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	disbursement, exists := ld.Disbursements[disbursementID]
	if !exists {
		return errors.New("disbursement not found")
	}

	if disbursement.Status != "Processed" {
		return errors.New("only processed disbursements can be completed")
	}

	disbursement.Status = "Completed"
	ld.Disbursements[disbursementID] = disbursement
	return nil
}

const (
    Active   LoanStatus = "active"
    Defaulted LoanStatus = "defaulted"
    PaidOff  LoanStatus = "paid_off"
)


func (lm *LoanMonitor) AddLoan(loan Loan) {
    lm.Loans = append(lm.Loans, loan)
}

func (lm *LoanMonitor) CheckRepayments() {
    for i := range lm.Loans {
        loan := &lm.Loans[i]
        for j := range loan.RepaymentPlan {
            repayment := &loan.RepaymentPlan[j]
            if !repayment.Paid && time.Now().After(repayment.DueDate) {
                fmt.Printf("Loan %s has a missed repayment due on %s\n", loan.ID, repayment.DueDate)
                // Add logic to handle missed repayments, e.g., notifications, penalties
            }
        }
    }
}

func (lm *LoanMonitor) UpdateLoanStatus(loanID string, status LoanStatus) error {
    for i := range lm.Loans {
        if lm.Loans[i].ID == loanID {
            lm.Loans[i].Status = status
            return nil
        }
    }
    return errors.New("loan not found")
}

func (lm *LoanMonitor) SecureCollateral(loanID string, collateralID string) error {
    for i := range lm.Loans {
        if lm.Loans[i].ID == loanID {
            for j := range lm.Loans[i].Collateral {
                if lm.Loans[i].Collateral[j].ID == collateralID && !lm.Loans[i].Collateral[j].IsSecured {
                    lm.Loans[i].Collateral[j].IsSecured = true
                    now := time.Now()
                    lm.Loans[i].Collateral[j].SecuredDate = &now
                    return nil
                }
            }
        }
    }
    return errors.New("loan or collateral not found")
}

func (lm *LoanMonitor) MonitorCollateral() {
    for i := range lm.Loans {
        loan := &lm.Loans[i]
        for j := range loan.Collateral {
            collateral := &loan.Collateral[j]
            if collateral.IsSecured {
                fmt.Printf("Monitoring secured collateral %s for loan %s\n", collateral.ID, loan.ID)
                // Add logic to monitor collateral value, e.g., AI-driven valuation updates
            }
        }
    }
}

func (lm *LoanMonitor) GenerateRepaymentSchedule(loan *Loan) {
    monthlyPayment := (loan.Amount * (1 + (loan.InterestRate / 100))) / float64(loan.Term)
    for i := 0; i < loan.Term; i++ {
        dueDate := loan.StartDate.AddDate(0, i+1, 0)
        loan.RepaymentPlan = append(loan.RepaymentPlan, Repayment{
            DueDate: dueDate,
            Amount:  monthlyPayment,
            Paid:    false,
        })
    }
}

func (lm *LoanMonitor) LiquidateCollateral(loanID string) error {
    for i := range lm.Loans {
        loan := &lm.Loans[i]
        if loan.ID == loanID && loan.Status == Defaulted {
            for j := range loan.Collateral {
                collateral := &loan.Collateral[j]
                if collateral.IsSecured {
                    fmt.Printf("Liquidating collateral %s for loan %s\n", collateral.ID, loan.ID)
                    // Add logic for liquidation, e.g., selling collateral and repaying the loan
                }
            }
            return nil
        }
    }
    return errors.New("loan not found or not defaulted")
}

// Function to monitor loan statuses
func (lm *LoanMonitor) MonitorLoanStatuses() {
    for i := range lm.Loans {
        loan := &lm.Loans[i]
        if time.Now().After(loan.EndDate) && loan.Status == Active {
            allPaid := true
            for _, repayment := range loan.RepaymentPlan {
                if !repayment.Paid {
                    allPaid = false
                    break
                }
            }
            if allPaid {
                loan.Status = PaidOff
                fmt.Printf("Loan %s has been fully repaid and is now marked as paid off\n", loan.ID)
            } else {
                loan.Status = Defaulted
                fmt.Printf("Loan %s has defaulted\n", loan.ID)
                // Add additional handling for defaults, e.g., initiating collateral liquidation
            }
        }
    }
}

// Function to notify users of upcoming repayments
func (lm *LoanMonitor) NotifyUpcomingRepayments() {
    for i := range lm.Loans {
        loan := &lm.Loans[i]
        for j := range loan.RepaymentPlan {
            repayment := &loan.RepaymentPlan[j]
            if !repayment.Paid && time.Until(repayment.DueDate).Hours() <= 72 {
                fmt.Printf("Notifying borrower %s of upcoming repayment for loan %s due on %s\n", loan.Borrower, loan.ID, repayment.DueDate)
                // Add notification logic, e.g., sending emails or in-app notifications
            }
        }
    }
}

// NewLoanMonitoring initializes a new LoanMonitoring instance.
func NewLoanMonitoring(loanID, borrowerID string, collateral Collateral) *LoanMonitoring {
	return &LoanMonitoring{
		LoanID:      loanID,
		BorrowerID:  borrowerID,
		Status:      Active,
		LastUpdated: time.Now(),
		NextDueDate: time.Now().AddDate(0, 1, 0), // Assuming monthly payments
		Collateral:  collateral,
	}
}

// UpdatePaymentHistory updates the payment history of the loan.
func (lm *LoanMonitoring) UpdatePaymentHistory(payment Payment) {
	lm.PaymentHistory = append(lm.PaymentHistory, payment)
	lm.LastUpdated = time.Now()
}

// SetStatus sets the status of the loan.
func (lm *LoanMonitoring) SetStatus(status LoanStatus) {
	lm.Status = status
	lm.LastUpdated = time.Now()
}

// SendNotification sends a notification related to the loan.
func (lm *LoanMonitoring) SendNotification(notificationType, message string) {
	notification := Notification{
		Type:    notificationType,
		Message: message,
		Date:    time.Now(),
	}
	lm.Notifications = append(lm.Notifications, notification)
}


// SendNotification sends a notification related to the loan.
func (lm *LoanMonitoring) SendNotification(notificationType, message string) {
	notification := Notification{
		Type:    notificationType,
		Message: message,
		Date:    time.Now(),
	}
	lm.Notifications = append(lm.Notifications, notification)
}

// CheckCollateralValue checks and updates the value of the collateral.
func (lm *LoanMonitoring) CheckCollateralValue() error {
	// Placeholder for actual collateral value check
	// For example, fetch current value from a market data provider
	currentValue := lm.Collateral.Value * 1.02 // Assuming a 2% increase for demonstration
	if currentValue < lm.Collateral.Value {
		lm.SendNotification("Collateral Alert", "The value of your collateral has decreased.")
		return errors.New("collateral value has decreased")
	}
	lm.Collateral.Value = currentValue
	lm.Collateral.UpdatedAt = time.Now()
	lm.LastUpdated = time.Now()
	return nil
}

// GenerateReport generates a report of the loan status.
func (lm *LoanMonitoring) GenerateReport() (string, error) {
	report, err := json.Marshal(lm)
	if err != nil {
		return "", err
	}
	return string(report), nil
}

// MonitorLoan handles the monitoring logic for the loan.
func MonitorLoan(loanID string) (*LoanMonitoring, error) {
	loan, err := loanpool.GetLoan(loanID)
	if err != nil {
		return nil, err
	}

	lm := NewLoanMonitoring(loan.ID, loan.BorrowerID, loan.Collateral)
	// Check collateral value
	if err := lm.CheckCollateralValue(); err != nil {
		return nil, err
	}

	// Placeholder for additional monitoring logic
	// ...

	// Generate a report
	report, err := lm.GenerateReport()
	if err != nil {
		return nil, err
	}
	fmt.Println("Loan Monitoring Report: ", report)

	return lm, nil
}

// PaymentProcessing handles the payment processing logic.
func PaymentProcessing(loanID string, amount float64) error {
	loan, err := loanpool.GetLoan(loanID)
	if err != nil {
		return err
	}

	lm := NewLoanMonitoring(loan.ID, loan.BorrowerID, loan.Collateral)
	payment := Payment{
		Date:   time.Now(),
		Amount: amount,
		Status: "Completed",
	}
	lm.UpdatePaymentHistory(payment)

	if amount < loan.NextDueAmount {
		lm.SendNotification("Payment Alert", "Your payment is less than the due amount.")
		return errors.New("payment amount is less than due amount")
	}

	loanpool.UpdateLoan(loan)
	return nil
}

// SendDueDateReminder sends a reminder for the due date.
func SendDueDateReminder(loanID string) error {
	loan, err := loanpool.GetLoan(loanID)
	if err != nil {
		return err
	}

	lm := NewLoanMonitoring(loan.ID, loan.BorrowerID, loan.Collateral)
	lm.SendNotification("Payment Reminder", "Your loan payment is due soon.")
	return nil
}

// ReplicateLoan replicates an existing loan into new tokens that can be traded on the secondary market.
func (lrs *LoanReplicationService) ReplicateLoan(loanID string, replicationFactor int) ([]models.LoanToken, error) {
	loan, err := lrs.BlockchainClient.GetLoan(loanID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch loan: %v", err)
	}

	if loan.Status != models.LoanActive {
		return nil, errors.New("only active loans can be replicated")
	}

	tokens := make([]models.LoanToken, replicationFactor)
	for i := 0; i < replicationFactor; i++ {
		token := models.LoanToken{
			ID:       fmt.Sprintf("%s-%d", loan.ID, i+1),
			LoanID:   loan.ID,
			Value:    loan.Amount / float64(replicationFactor),
			Owner:    loan.Owner,
			Created:  time.Now(),
			Status:   models.TokenActive,
			Collateral: loan.Collateral,
		}
		tokens[i] = token
	}

	err = lrs.BlockchainClient.MintLoanTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("failed to mint loan tokens: %v", err)
	}

	return tokens, nil
}

// ValidateReplication ensures that the replication of a loan meets all necessary criteria.
func (lrs *LoanReplicationService) ValidateReplication(loan models.Loan, replicationFactor int) error {
	if loan.Amount <= 0 {
		return errors.New("loan amount must be greater than zero")
	}
	if replicationFactor <= 0 {
		return errors.New("replication factor must be greater than zero")
	}
	if loan.Status != models.LoanActive {
		return errors.New("only active loans can be replicated")
	}
	return nil
}

// MonitorReplicatedLoans monitors the status of replicated loans and provides real-time updates.
func (lrs *LoanReplicationService) MonitorReplicatedLoans() error {
	loans, err := lrs.BlockchainClient.GetAllLoans()
	if err != nil {
		return fmt.Errorf("failed to fetch loans: %v", err)
	}

	for _, loan := range loans {
		if loan.Status == models.LoanReplicated {
			status, err := lrs.BlockchainClient.GetLoanStatus(loan.ID)
			if err != nil {
				return fmt.Errorf("failed to get loan status: %v", err)
			}

			if status == models.LoanDefaulted {
				err := lrs.HandleDefaultedLoan(loan)
				if err != nil {
					return fmt.Errorf("failed to handle defaulted loan: %v", err)
				}
			}
		}
	}
	return nil
}

// HandleDefaultedLoan handles the process when a replicated loan defaults.
func (lrs *LoanReplicationService) HandleDefaultedLoan(loan models.Loan) error {
	tokens, err := lrs.BlockchainClient.GetLoanTokens(loan.ID)
	if err != nil {
		return fmt.Errorf("failed to get loan tokens: %v", err)
	}

	for _, token := range tokens {
		err := lrs.BlockchainClient.LiquidateCollateral(token)
		if err != nil {
			return fmt.Errorf("failed to liquidate collateral: %v", err)
		}
	}

	return nil
}

// NotifyStakeholders sends notifications to stakeholders regarding loan replication and status changes.
func (lrs *LoanReplicationService) NotifyStakeholders(loanID, message string) error {
	loan, err := lrs.BlockchainClient.GetLoan(loanID)
	if err != nil {
		return fmt.Errorf("failed to fetch loan: %v", err)
	}

	stakeholders := loan.GetStakeholders()
	for _, stakeholder := range stakeholders {
		err := lrs.BlockchainClient.SendNotification(stakeholder, message)
		if err != nil {
			return fmt.Errorf("failed to send notification: %v", err)
		}
	}

	return nil
}

// RequestReschedule allows borrowers to request a new repayment schedule
func RequestReschedule(loanID, reason string, newSchedule RepaymentSchedule) (*LoanRescheduling, error) {
    // Verify borrower's identity using SYN900 tokens
    borrower, err := users.VerifyUser(loanID)
    if err != nil {
        return nil, errors.New("user verification failed")
    }

    // Fetch the original loan details
    loan, err := blockchain.FetchLoanDetails(loanID)
    if err != nil {
        return nil, errors.New("failed to fetch loan details")
    }

    // Ensure that the new schedule complies with the platform's rules
    err = validateNewSchedule(newSchedule)
    if err != nil {
        return nil, err
    }

    // Create the rescheduling request
    reschedule := &LoanRescheduling{
        LoanID:           loanID,
        OriginalSchedule: loan.RepaymentSchedule,
        NewSchedule:      newSchedule,
        RescheduleDate:   time.Now(),
        Reason:           reason,
        Approved:         false,
    }

    // Log the reschedule request in the blockchain for transparency and immutability
    err = blockchain.LogRescheduleRequest(reschedule)
    if err != nil {
        return nil, errors.New("failed to log reschedule request on blockchain")
    }

    // Notify authority nodes for approval
    err = notifications.NotifyAuthorityNodes("New loan rescheduling request", reschedule)
    if err != nil {
        return nil, errors.New("failed to notify authority nodes")
    }

    return reschedule, nil
}

// ApproveReschedule allows authority nodes to approve rescheduling requests
func ApproveReschedule(reschedule *LoanRescheduling) error {
    // Verify the authority node's identity and permission
    authorityNode, err := users.VerifyAuthorityNode()
    if err != nil {
        return errors.New("authority node verification failed")
    }

    // Check if the reschedule request is already approved
    if reschedule.Approved {
        return errors.New("reschedule request already approved")
    }

    // Approve the reschedule request
    reschedule.Approved = true
    reschedule.ApprovalTimestamp = time.Now()

    // Update the loan details on the blockchain
    err = blockchain.UpdateLoanRepaymentSchedule(reschedule.LoanID, reschedule.NewSchedule)
    if err != nil {
        return errors.New("failed to update loan repayment schedule on blockchain")
    }

    // Notify the borrower about the approval
    borrower, err := users.FetchUserDetails(reschedule.LoanID)
    if err != nil {
        return errors.New("failed to fetch borrower details")
    }

    err = notifications.SendNotification(borrower.Email, "Loan Reschedule Approved", "Your loan rescheduling request has been approved.")
    if err != nil {
        return errors.New("failed to notify borrower")
    }

    return nil
}

// validateNewSchedule validates the new repayment schedule
func validateNewSchedule(schedule RepaymentSchedule) error {
    // Ensure the new schedule is logical and payments are feasible
    for _, paymentAmount := range schedule.PaymentAmounts {
        if paymentAmount.Cmp(big.NewInt(0)) <= 0 {
            return errors.New("payment amount must be greater than zero")
        }
    }

    // Ensure the payment dates are in the future
    now := time.Now()
    for _, paymentDate := range schedule.PaymentDates {
        if paymentDate.Before(now) {
            return errors.New("payment date must be in the future")
        }
    }

    return nil
}

// FetchRescheduleRequest fetches the reschedule request details
func FetchRescheduleRequest(loanID string) (*LoanRescheduling, error) {
    // Fetch the reschedule request from the blockchain
    reschedule, err := blockchain.FetchRescheduleRequest(loanID)
    if err != nil {
        return nil, errors.New("failed to fetch reschedule request from blockchain")
    }
    return reschedule, nil
}


// Initialize a new loan settlement
func NewLoanSettlement(loanID, borrowerID, lenderID string, amount, interestRate float64, duration time.Duration, collateral []collateral_management.Collateral) *LoanSettlement {
	startDate := time.Now()
	endDate := startDate.Add(duration)
	repaymentSchedule := calculateRepaymentSchedule(amount, interestRate, duration, startDate)

	return &LoanSettlement{
		LoanID:           loanID,
		BorrowerID:       borrowerID,
		LenderID:         lenderID,
		Amount:           amount,
		InterestRate:     interestRate,
		Duration:         duration,
		StartDate:        startDate,
		EndDate:          endDate,
		RepaymentSchedule: repaymentSchedule,
		Collateral:       collateral,
	}
}

// Calculate the repayment schedule
func calculateRepaymentSchedule(amount, interestRate float64, duration time.Duration, startDate time.Time) map[time.Time]float64 {
	repayments := make(map[time.Time]float64)
	monthlyInterestRate := interestRate / 12
	numberOfMonths := int(duration.Hours() / 24 / 30)

	for i := 0; i < numberOfMonths; i++ {
		repaymentDate := startDate.AddDate(0, i, 0)
		repaymentAmount := (amount / float64(numberOfMonths)) * (1 + monthlyInterestRate)
		repayments[repaymentDate] = repaymentAmount
	}
	return repayments
}

// Process a repayment
func (ls *LoanSettlement) ProcessRepayment(amount float64) error {
	today := time.Now()
	for date, repayment := range ls.RepaymentSchedule {
		if today.After(date) || today.Equal(date) {
			if amount < repayment {
				return errors.New("repayment amount is less than the scheduled repayment")
			}
			ls.Amount -= repayment
			delete(ls.RepaymentSchedule, date)
			notification_system.SendRepaymentConfirmation(ls.BorrowerID, ls.LoanID, repayment)
			notification_system.SendRepaymentReceipt(ls.LenderID, ls.LoanID, repayment)
			break
		}
	}
	if ls.Amount <= 0 {
		err := ls.SettleLoan()
		if err != nil {
			return err
		}
	}
	return nil
}

// Settle the loan
func (ls *LoanSettlement) SettleLoan() error {
	// Release collateral
	err := collateral_management.ReleaseCollateral(ls.Collateral)
	if err != nil {
		return err
	}

	// Send notifications
	notification_system.SendLoanSettlementConfirmation(ls.BorrowerID, ls.LoanID)
	notification_system.SendLoanSettlementNotification(ls.LenderID, ls.LoanID)

	return nil
}

// Encrypt sensitive information
func (ls *LoanSettlement) EncryptSensitiveData(key []byte) error {
	encryptedLoanID, err := encryption.Encrypt([]byte(ls.LoanID), key)
	if err != nil {
		return err
	}
	ls.LoanID = string(encryptedLoanID)

	encryptedBorrowerID, err := encryption.Encrypt([]byte(ls.BorrowerID), key)
	if err != nil {
		return err
	}
	ls.BorrowerID = string(encryptedBorrowerID)

	encryptedLenderID, err := encryption.Encrypt([]byte(ls.LenderID), key)
	if err != nil {
		return err
	}
	ls.LenderID = string(encryptedLenderID)

	return nil
}

// Decrypt sensitive information
func (ls *LoanSettlement) DecryptSensitiveData(key []byte) error {
	decryptedLoanID, err := encryption.Decrypt([]byte(ls.LoanID), key)
	if err != nil {
		return err
	}
	ls.LoanID = string(decryptedLoanID)

	decryptedBorrowerID, err := encryption.Decrypt([]byte(ls.BorrowerID), key)
	if err != nil {
		return err
	}
	ls.BorrowerID = string(decryptedBorrowerID)

	decryptedLenderID, err := encryption.Decrypt([]byte(ls.LenderID), key)
	if err != nil {
		return err
	}
	ls.LenderID = string(decryptedLenderID)

	return nil
}

// Validate the loan settlement
func (ls *LoanSettlement) Validate() error {
	if ls.LoanID == "" || ls.BorrowerID == "" || ls.LenderID == "" || ls.Amount <= 0 || ls.InterestRate < 0 {
		return errors.New("invalid loan settlement details")
	}
	return nil
}

