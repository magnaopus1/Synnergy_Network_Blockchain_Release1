package loanpool_core

import (
	"errors"
	"sync"
	"time"
)

// NewEducationGrantManager initializes a new EducationGrantManager instance.
func NewEducationGrantManager() *EducationGrantManager {
	return &EducationGrantManager{
		grants:  make(map[string]*EducationGrant),
		reports: make(map[string][]ProgressReport),
	}
}

// SubmitGrantProposal allows a user to submit a proposal for an education grant.
func (egm *EducationGrantManager) SubmitGrantProposal(applicantID, purpose string, amount float64) (string, error) {
	egm.mu.Lock()
	defer egm.mu.Unlock()

	grantID := generateID()
	grant := &EducationGrant{
		ID:            grantID,
		ApplicantID:   applicantID,
		Amount:        amount,
		Purpose:       purpose,
		Status:        "Submitted",
		SubmissionDate: time.Now(),
	}

	egm.grants[grantID] = grant
	return grantID, nil
}

// ApproveGrantProposal approves a submitted grant proposal.
func (egm *EducationGrantManager) ApproveGrantProposal(grantID string) error {
	egm.mu.Lock()
	defer egm.mu.Unlock()

	grant, exists := egm.grants[grantID]
	if !exists {
		return errors.New("grant not found")
	}

	if grant.Status != "Submitted" {
		return errors.New("grant cannot be approved in its current status")
	}

	now := time.Now()
	grant.Status = "Approved"
	grant.ApprovalDate = &now
	return nil
}

// DisburseGrant disburses the approved grant to the applicant.
func (egm *EducationGrantManager) DisburseGrant(grantID string) error {
	egm.mu.Lock()
	defer egm.mu.Unlock()

	grant, exists := egm.grants[grantID]
	if !exists {
		return errors.New("grant not found")
	}

	if grant.Status != "Approved" {
		return errors.New("grant cannot be disbursed in its current status")
	}

	now := time.Now()
	grant.Status = "Disbursed"
	grant.DisbursementDate = &now
	return nil
}

// SubmitProgressReport allows an applicant to submit a progress report on the grant usage.
func (egm *EducationGrantManager) SubmitProgressReport(grantID, content string) (string, error) {
	egm.mu.Lock()
	defer egm.mu.Unlock()

	grant, exists := egm.grants[grantID]
	if !exists {
		return "", errors.New("grant not found")
	}

	if grant.Status != "Disbursed" {
		return "", errors.New("progress reports can only be submitted for disbursed grants")
	}

	reportID := generateID()
	report := ProgressReport{
		ID:        reportID,
		GrantID:   grantID,
		ReportDate: time.Now(),
		Content:   content,
	}

	egm.reports[grantID] = append(egm.reports[grantID], report)
	grant.Reports = append(grant.Reports, report)
	return reportID, nil
}

// ReviewProgressReport reviews the submitted progress reports for a grant.
func (egm *EducationGrantManager) ReviewProgressReport(grantID string) ([]ProgressReport, error) {
	egm.mu.Lock()
	defer egm.mu.Unlock()

	reports, exists := egm.reports[grantID]
	if !exists {
		return nil, errors.New("no reports found for the specified grant")
	}

	return reports, nil
}

// generateID generates a unique ID for grants and reports.
func generateID() string {
	// Implement unique ID generation logic (e.g., UUID)
	return "unique-id-placeholder"
}

// InitializeGrant initializes a new grant loan
func InitializeGrant(proposalID string, amount float64, recipient string) *GrantLoan {
    return &GrantLoan{
        GrantID:        utils.GenerateID(),
        ProposalID:     proposalID,
        Amount:         amount,
        Recipient:      recipient,
        Status:         "Initialized",
        DisbursementDate: time.Time{},
        ReportingDue:   time.Time{},
        Reports:        make([]string, 0),
    }
}

// ApproveGrant approves the grant and schedules disbursement
func (gl *GrantLoan) ApproveGrant() error {
    if gl.Status != "Initialized" {
        return errors.New("grant is not in an initializable state")
    }
    
    gl.Status = "Approved"
    gl.DisbursementDate = time.Now().Add(7 * 24 * time.Hour) // Schedule disbursement in one week

    // Store approval details in the blockchain
    err := smartcontracts.StoreGrantApprovalDetails(gl)
    if err != nil {
        return fmt.Errorf("failed to store grant approval details: %v", err)
    }

    // Notify the recipient about the approval
    notifications.SendGrantApprovalNotification(gl.Recipient, gl.GrantID)

    return nil
}

// DisburseGrant disburses the grant to the recipient
func (gl *GrantLoan) DisburseGrant() error {
    if gl.Status != "Approved" {
        return errors.New("grant is not approved for disbursement")
    }
    
    if time.Now().Before(gl.DisbursementDate) {
        return errors.New("disbursement date has not been reached")
    }

    gl.Status = "Disbursed"
    gl.ReportingDue = time.Now().Add(30 * 24 * time.Hour) // Reporting due in one month

    // Transfer funds to the recipient
    err := smartcontracts.DisburseGrantFunds(gl.Recipient, gl.Amount)
    if err != nil {
        return fmt.Errorf("failed to disburse grant funds: %v", err)
    }

    // Notify the recipient about the disbursement
    notifications.SendGrantDisbursementNotification(gl.Recipient, gl.GrantID)

    return nil
}

// SubmitReport allows the recipient to submit a report on the grant usage
func (gl *GrantLoan) SubmitReport(report string) error {
    if gl.Status != "Disbursed" {
        return errors.New("grant has not been disbursed yet")
    }

    gl.Reports = append(gl.Reports, report)

    // Store report details in the blockchain
    err := smartcontracts.StoreGrantReport(gl.GrantID, report)
    if err != nil {
        return fmt.Errorf("failed to store grant report: %v", err)
    }

    // Notify the authority about the new report
    notifications.SendGrantReportNotification(gl.GrantID, report)

    return nil
}

// ReviewReports allows the authority to review the submitted reports
func (gl *GrantLoan) ReviewReports() ([]string, error) {
    if gl.Status != "Disbursed" && gl.Status != "Completed" {
        return nil, errors.New("grant has not reached a reviewable state")
    }

    // Decrypt and return the reports
    decryptedReports := make([]string, 0, len(gl.Reports))
    for _, report := range gl.Reports {
        decryptedReport, err := encryption.DecryptData(report)
        if err != nil {
            return nil, fmt.Errorf("failed to decrypt report: %v", err)
        }
        decryptedReports = append(decryptedReports, decryptedReport)
    }

    return decryptedReports, nil
}

// CompleteGrant marks the grant as completed after successful review of reports
func (gl *GrantLoan) CompleteGrant() error {
    if gl.Status != "Disbursed" {
        return errors.New("grant has not been disbursed yet")
    }

    gl.Status = "Completed"

    // Store completion details in the blockchain
    err := smartcontracts.StoreGrantCompletionDetails(gl)
    if err != nil {
        return fmt.Errorf("failed to store grant completion details: %v", err)
    }

    // Notify the recipient about the completion
    notifications.SendGrantCompletionNotification(gl.Recipient, gl.GrantID)

    return nil
}

// ResolveGrantIssues handles resolution of any issues found with the grant
func (gl *GrantLoan) ResolveGrantIssues(issueDescription string) error {
    gl.Status = "IssueResolved"

    // Encrypt the updated grant report
    encryptedReport, err := encryption.EncryptData(issueDescription)
    if err != nil {
        return fmt.Errorf("failed to encrypt updated grant report: %v", err)
    }

    // Store issue resolution details in the blockchain
    err = smartcontracts.StoreGrantIssueResolution(gl.GrantID, encryptedReport)
    if err != nil {
        return fmt.Errorf("failed to store grant issue resolution: %v", err)
    }

    // Notify relevant parties
    notifications.SendGrantIssueResolutionNotification(gl.GrantID, issueDescription)

    return nil
}

// InitializeLoanRelease initializes a new loan release process
func InitializeLoanRelease(borrowerID string, amount float64, repaymentPlan RepaymentPlan, collateralID string) *LoanRelease {
    return &LoanRelease{
        LoanID:           utils.GenerateID(),
        BorrowerID:       borrowerID,
        Amount:           amount,
        DisbursementDate: time.Now(),
        RepaymentPlan:    repaymentPlan,
        Status:           "Initialized",
        CollateralID:     collateralID,
    }
}

// ApproveLoan approves the loan and schedules disbursement
func (lr *LoanRelease) ApproveLoan() error {
    if lr.Status != "Initialized" {
        return errors.New("loan is not in an initializable state")
    }

    lr.Status = "Approved"
    lr.DisbursementDate = time.Now()

    // Store approval details in the blockchain
    err := smartcontracts.StoreLoanApprovalDetails(lr)
    if err != nil {
        return fmt.Errorf("failed to store loan approval details: %v", err)
    }

    // Notify the borrower about the approval
    notifications.SendLoanApprovalNotification(lr.BorrowerID, lr.LoanID)

    return nil
}

// DisburseLoan disburses the loan to the borrower
func (lr *LoanRelease) DisburseLoan() error {
    if lr.Status != "Approved" {
        return errors.New("loan is not approved for disbursement")
    }

    lr.Status = "Disbursed"

    // Transfer funds to the borrower
    err := smartcontracts.DisburseLoanFunds(lr.BorrowerID, lr.Amount)
    if err != nil {
        return fmt.Errorf("failed to disburse loan funds: %v", err)
    }

    // Notify the borrower about the disbursement
    notifications.SendLoanDisbursementNotification(lr.BorrowerID, lr.LoanID)

    return nil
}

// RecordRepayment records a repayment made by the borrower
func (lr *LoanRelease) RecordRepayment(amount float64, paymentDate time.Time) error {
    if lr.Status != "Disbursed" {
        return errors.New("loan has not been disbursed yet")
    }

    for i, schedule := range lr.RepaymentPlan.Schedule {
        if !schedule.Paid && paymentDate.Before(schedule.DueDate) {
            lr.RepaymentPlan.Schedule[i].Paid = true
            lr.RepaymentPlan.Schedule[i].PaidDate = paymentDate
            lr.RepaymentPlan.TotalPaid += amount

            // Store repayment details in the blockchain
            err := smartcontracts.StoreRepaymentDetails(lr.LoanID, amount, paymentDate)
            if err != nil {
                return fmt.Errorf("failed to store repayment details: %v", err)
            }

            // Notify the borrower about the recorded repayment
            notifications.SendRepaymentNotification(lr.BorrowerID, lr.LoanID, amount)

            return nil
        }
    }

    return errors.New("no due repayment found for the given date")
}

// CompleteLoan marks the loan as completed after all repayments are made
func (lr *LoanRelease) CompleteLoan() error {
    if lr.Status != "Disbursed" {
        return errors.New("loan has not been disbursed yet")
    }

    // Check if all repayments are made
    for _, schedule := range lr.RepaymentPlan.Schedule {
        if !schedule.Paid {
            return errors.New("not all repayments have been made")
        }
    }

    lr.Status = "Completed"

    // Store completion details in the blockchain
    err := smartcontracts.StoreLoanCompletionDetails(lr)
    if err != nil {
        return fmt.Errorf("failed to store loan completion details: %v", err)
    }

    // Release collateral
    err = smartcontracts.ReleaseCollateral(lr.CollateralID)
    if err != nil {
        return fmt.Errorf("failed to release collateral: %v", err)
    }

    // Notify the borrower about the loan completion
    notifications.SendLoanCompletionNotification(lr.BorrowerID, lr.LoanID)

    return nil
}

// HandleLatePayment handles penalties and notifications for late payments
func (lr *LoanRelease) HandleLatePayment() error {
    for i, schedule := range lr.RepaymentPlan.Schedule {
        if !schedule.Paid && time.Now().After(schedule.DueDate) {
            // Apply late payment penalty
            penaltyAmount := schedule.Amount * 0.05 // 5% penalty
            err := smartcontracts.ApplyLatePaymentPenalty(lr.LoanID, penaltyAmount)
            if err != nil {
                return fmt.Errorf("failed to apply late payment penalty: %v", err)
            }

            // Notify the borrower about the late payment penalty
            notifications.SendLatePaymentNotification(lr.BorrowerID, lr.LoanID, penaltyAmount)

            // Update schedule to reflect penalty
            lr.RepaymentPlan.Schedule[i].Amount += penaltyAmount
        }
    }

    return nil
}

// EncryptLoanDetails encrypts loan details for secure storage
func (lr *LoanRelease) EncryptLoanDetails() error {
    encryptedLoanDetails, err := encryption.EncryptData(fmt.Sprintf("%v", lr))
    if err != nil {
        return fmt.Errorf("failed to encrypt loan details: %v", err)
    }

    lr.Status = encryptedLoanDetails

    return nil
}

// DecryptLoanDetails decrypts loan details for viewing
func (lr *LoanRelease) DecryptLoanDetails() (string, error) {
    decryptedLoanDetails, err := encryption.DecryptData(lr.Status)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt loan details: %v", err)
    }

    return decryptedLoanDetails, nil
}

// InitializeLoanPool initializes a new loan pool
func InitializeLoanPool() *LoanPool {
    return &LoanPool{
        PoolID:         utils.GenerateID(),
        Loans:          make(map[string]*Loan),
        Governance:     Governance{Proposals: make(map[string]Proposal)},
        Securitization: Securitization{TokenizedLoans: make(map[string]TokenizedLoan)},
        Notifications:  NotificationSystem{Subscribers: make(map[string][]Notification)},
    }
}

// SubmitProposal submits a new proposal for governance
func (lp *LoanPool) SubmitProposal(description, submitter string) string {
    proposalID := utils.GenerateID()
    lp.Governance.Proposals[proposalID] = Proposal{
        ProposalID:  proposalID,
        Description: description,
        Submitter:   submitter,
        Status:      "Pending",
    }
    return proposalID
}

// VoteOnProposal allows voting on a proposal
func (lp *LoanPool) VoteOnProposal(proposalID, voterID string, voteFor bool) error {
    proposal, exists := lp.Governance.Proposals[proposalID]
    if !exists {
        return errors.New("proposal does not exist")
    }

    if voteFor {
        proposal.VotesFor++
    } else {
        proposal.VotesAgainst++
    }

    if proposal.VotesFor >= 3 {
        proposal.Status = "Approved"
        lp.NotifySubscribers("Proposal Approved", fmt.Sprintf("Proposal %s has been approved.", proposalID))
    } else if proposal.VotesAgainst >= 3 {
        proposal.Status = "Rejected"
        lp.NotifySubscribers("Proposal Rejected", fmt.Sprintf("Proposal %s has been rejected.", proposalID))
    }

    lp.Governance.Proposals[proposalID] = proposal
    return nil
}

// DisburseLoan disburses the loan to the borrower
func (lp *LoanPool) DisburseLoan(loanID string) error {
    loan, exists := lp.Loans[loanID]
    if !exists {
        return errors.New("loan does not exist")
    }

    if loan.Status != "Approved" {
        return errors.New("loan is not approved for disbursement")
    }

    loan.Status = "Disbursed"
    loan.DisbursementDate = time.Now()

    // Transfer funds to the borrower
    err := smartcontracts.DisburseLoanFunds(loan.BorrowerID, loan.Amount)
    if err != nil {
        return fmt.Errorf("failed to disburse loan funds: %v", err)
    }

    lp.Loans[loanID] = loan
    lp.NotifySubscribers("Loan Disbursed", fmt.Sprintf("Loan %s has been disbursed to borrower %s.", loanID, loan.BorrowerID))
    return nil
}

// RecordRepayment records a repayment made by the borrower
func (lp *LoanPool) RecordRepayment(loanID string, amount float64, paymentDate time.Time) error {
    loan, exists := lp.Loans[loanID]
    if !exists {
        return errors.New("loan does not exist")
    }

    for i, schedule := range loan.RepaymentPlan.Schedule {
        if !schedule.Paid && paymentDate.Before(schedule.DueDate) {
            loan.RepaymentPlan.Schedule[i].Paid = true
            loan.RepaymentPlan.Schedule[i].PaidDate = paymentDate
            loan.RepaymentPlan.TotalPaid += amount

            // Store repayment details in the blockchain
            err := smartcontracts.StoreRepaymentDetails(loanID, amount, paymentDate)
            if err != nil {
                return fmt.Errorf("failed to store repayment details: %v", err)
            }

            lp.Loans[loanID] = loan
            lp.NotifySubscribers("Repayment Recorded", fmt.Sprintf("Repayment of %f for loan %s has been recorded.", amount, loanID))
            return nil
        }
    }

    return errors.New("no due repayment found for the given date")
}

// CompleteLoan marks the loan as completed after all repayments are made
func (lp *LoanPool) CompleteLoan(loanID string) error {
    loan, exists := lp.Loans[loanID]
    if !exists {
        return errors.New("loan does not exist")
    }

    // Check if all repayments are made
    for _, schedule := range loan.RepaymentPlan.Schedule {
        if !schedule.Paid {
            return errors.New("not all repayments have been made")
        }
    }

    loan.Status = "Completed"

    // Store completion details in the blockchain
    err := smartcontracts.StoreLoanCompletionDetails(loan)
    if err != nil {
        return fmt.Errorf("failed to store loan completion details: %v", err)
    }

    // Release collateral
    err = smartcontracts.ReleaseCollateral(loan.CollateralID)
    if err != nil {
        return fmt.Errorf("failed to release collateral: %v", err)
    }

    lp.Loans[loanID] = loan
    lp.NotifySubscribers("Loan Completed", fmt.Sprintf("Loan %s has been completed.", loanID))
    return nil
}

// NotifySubscribers sends notifications to subscribers
func (lp *LoanPool) NotifySubscribers(notificationType, message string) {
    notificationID := utils.GenerateID()
    notification := Notification{
        NotificationID: notificationID,
        Type:           notificationType,
        Message:        message,
        Timestamp:      time.Now(),
    }

    for subscriberID := range lp.Notifications.Subscribers {
        lp.Notifications.Subscribers[subscriberID] = append(lp.Notifications.Subscribers[subscriberID], notification)
    }
}

// Subscribe adds a user to the notification system
func (lp *LoanPool) Subscribe(userID string) {
    if _, exists := lp.Notifications.Subscribers[userID]; !exists {
        lp.Notifications.Subscribers[userID] = []Notification{}
    }
}


// InitializePovertyFund initializes the poverty fund with a specified allocation
func InitializePovertyFund(initialAmount float64) *PovertyFund {
	return &PovertyFund{
		FundID:          utils.GenerateID(),
		TotalAllocation: initialAmount,
		RemainingAmount: initialAmount,
	}
}

// SubmitPovertyLoanProposal submits a new proposal for a poverty loan
func (pf *PovertyFund) SubmitPovertyLoanProposal(borrowerID string, amount float64, grant bool) (string, error) {
	if amount > pf.RemainingAmount {
		return "", errors.New("insufficient funds in the poverty fund")
	}
	loanID := utils.GenerateID()
	loan := PovertyLoan{
		LoanID:           loanID,
		BorrowerID:       borrowerID,
		Amount:           amount,
		Status:           "Pending",
		Grant:            grant,
	}

	pf.RemainingAmount -= amount

	// Store loan proposal in governance system
	err := governance.StoreProposal(loan)
	if err != nil {
		return "", err
	}

	notifications.SendNotification(borrowerID, "Poverty Loan Proposal Submitted", "Your poverty loan proposal has been submitted for review.")
	return loanID, nil
}

// ApprovePovertyLoanProposal approves a poverty loan proposal
func (pf *PovertyFund) ApprovePovertyLoanProposal(loanID string) error {
	loan, err := governance.GetProposal(loanID)
	if err != nil {
		return err
	}

	if loan.Status != "Pending" {
		return errors.New("loan proposal is not in pending status")
	}

	loan.Status = "Approved"
	loan.DisbursementDate = time.Now()

	// Disburse funds
	err = smartcontracts.DisburseLoanFunds(loan.BorrowerID, loan.Amount)
	if err != nil {
		return err
	}

	// Store the approved loan
	err = governance.StoreApprovedLoan(loan)
	if err != nil {
		return err
	}

	notifications.SendNotification(loan.BorrowerID, "Poverty Loan Approved", "Your poverty loan has been approved and funds have been disbursed.")
	return nil
}

// RejectPovertyLoanProposal rejects a poverty loan proposal
func (pf *PovertyFund) RejectPovertyLoanProposal(loanID string) error {
	loan, err := governance.GetProposal(loanID)
	if err != nil {
		return err
	}

	if loan.Status != "Pending" {
		return errors.New("loan proposal is not in pending status")
	}

	loan.Status = "Rejected"

	// Refund the amount to the fund
	pf.RemainingAmount += loan.Amount

	// Update the proposal status
	err = governance.UpdateProposalStatus(loanID, "Rejected")
	if err != nil {
		return err
	}

	notifications.SendNotification(loan.BorrowerID, "Poverty Loan Rejected", "Your poverty loan proposal has been rejected.")
	return nil
}

// RepayPovertyLoan handles the repayment of poverty loans, even though they are grants and non-repayable
func (pf *PovertyFund) RepayPovertyLoan(loanID string, amount float64) error {
	loan, err := governance.GetApprovedLoan(loanID)
	if err != nil {
		return err
	}

	if loan.Status != "Approved" {
		return errors.New("loan is not in approved status")
	}

	loan.Amount -= amount
	if loan.Amount <= 0 {
		loan.Status = "Completed"
	}

	// Update the loan details
	err = governance.UpdateApprovedLoan(loan)
	if err != nil {
		return err
	}

	notifications.SendNotification(loan.BorrowerID, "Poverty Loan Repayment", "Your repayment has been received.")
	return nil
}

// NewProposalManagement initializes a new ProposalManagement instance
func NewProposalManagement() *ProposalManagement {
	return &ProposalManagement{
		Proposals: []Proposal{},
	}
}

// SubmitProposal submits a new loan or grant proposal
func (pm *ProposalManagement) SubmitProposal(proposerID string, proposalType string, amount float64, requiredVotes int) (string, error) {
	if amount <= 0 {
		return "", errors.New("invalid proposal amount")
	}
	proposalID := utils.GenerateID()
	proposal := Proposal{
		ProposalID:    proposalID,
		ProposerID:    proposerID,
		Type:          proposalType,
		Amount:        amount,
		SubmittedDate: time.Now(),
		Status:        "Pending",
		Votes:         0,
		RequiredVotes: requiredVotes,
	}
	pm.Proposals = append(pm.Proposals, proposal)
	notifications.SendNotification(proposerID, "Proposal Submitted", "Your proposal has been submitted and is pending review.")
	return proposalID, nil
}

// VoteProposal allows node users to vote on a proposal
func (pm *ProposalManagement) VoteProposal(proposalID string, voterID string, vote bool) error {
	for i, proposal := range pm.Proposals {
		if proposal.ProposalID == proposalID {
			if proposal.Status != "Pending" {
				return errors.New("proposal is not in a pending state")
			}
			if vote {
				pm.Proposals[i].Votes++
			} else {
				pm.Proposals[i].Votes--
			}
			notifications.SendNotification(voterID, "Vote Cast", "Your vote has been recorded.")
			if pm.Proposals[i].Votes >= pm.Proposals[i].RequiredVotes {
				pm.Proposals[i].Status = "Approved"
				pm.Proposals[i].ApprovalDate = time.Now()
				notifications.SendNotification(proposal.ProposerID, "Proposal Approved", "Your proposal has been approved.")
				pm.ExecuteProposal(proposalID)
			} else if pm.Proposals[i].Votes <= -pm.Proposals[i].RequiredVotes {
				pm.Proposals[i].Status = "Rejected"
				notifications.SendNotification(proposal.ProposerID, "Proposal Rejected", "Your proposal has been rejected.")
			}
			return nil
		}
	}
	return errors.New("proposal not found")
}

// ExecuteProposal executes an approved proposal
func (pm *ProposalManagement) ExecuteProposal(proposalID string) error {
	for _, proposal := range pm.Proposals {
		if proposal.ProposalID == proposalID {
			if proposal.Status != "Approved" {
				return errors.New("proposal is not approved")
			}
			err := smartcontracts.ExecuteProposalContract(proposal.ProposerID, proposal.Type, proposal.Amount)
			if err != nil {
				return err
			}
			notifications.SendNotification(proposal.ProposerID, "Proposal Executed", "Your proposal has been executed and funds disbursed.")
			return nil
		}
	}
	return errors.New("proposal not found")
}

// GetProposalStatus retrieves the status of a proposal
func (pm *ProposalManagement) GetProposalStatus(proposalID string) (string, error) {
	for _, proposal := range pm.Proposals {
		if proposal.ProposalID == proposalID {
			return proposal.Status, nil
		}
	}
	return "", errors.New("proposal not found")
}

// ListProposals lists all proposals in the system
func (pm *ProposalManagement) ListProposals() []Proposal {
	return pm.Proposals
}

// GovernanceIntegration interfaces with the governance system
func (pm *ProposalManagement) GovernanceIntegration(proposalID string, action string) error {
	switch action {
	case "approve":
		return pm.ApproveProposal(proposalID)
	case "reject":
		return pm.RejectProposal(proposalID)
	default:
		return errors.New("invalid action")
	}
}

// ApproveProposal approves a proposal through governance
func (pm *ProposalManagement) ApproveProposal(proposalID string) error {
	for i, proposal := range pm.Proposals {
		if proposal.ProposalID == proposalID {
			if proposal.Status != "Pending" {
				return errors.New("proposal is not pending")
			}
			pm.Proposals[i].Status = "Approved"
			pm.Proposals[i].ApprovalDate = time.Now()
			notifications.SendNotification(proposal.ProposerID, "Proposal Approved", "Your proposal has been approved through governance.")
			return pm.ExecuteProposal(proposalID)
		}
	}
	return errors.New("proposal not found")
}

// RejectProposal rejects a proposal through governance
func (pm *ProposalManagement) RejectProposal(proposalID string) error {
	for i, proposal := range pm.Proposals {
		if proposal.ProposalID == proposalID {
			if proposal.Status != "Pending" {
				return errors.New("proposal is not pending")
			}
			pm.Proposals[i].Status = "Rejected"
			notifications.SendNotification(proposal.ProposerID, "Proposal Rejected", "Your proposal has been rejected through governance.")
			return nil
		}
	}
	return errors.New("proposal not found")
}

// NewSecuredLoanManagement initializes a new SecuredLoanManagement instance
func NewSecuredLoanManagement() *SecuredLoanManagement {
	return &SecuredLoanManagement{
		Loans: []SecuredLoan{},
	}
}

// CreateSecuredLoan creates a new secured loan
func (slm *SecuredLoanManagement) CreateSecuredLoan(borrowerID string, amount float64, collateral string, collateralType string, interestRate float64, durationDays int) (string, error) {
	if amount <= 0 {
		return "", errors.New("invalid loan amount")
	}

	loanID := utils.GenerateID()
	startDate := time.Now()
	endDate := startDate.AddDate(0, 0, durationDays)

	loan := SecuredLoan{
		LoanID:         loanID,
		BorrowerID:     borrowerID,
		Amount:         amount,
		Collateral:     collateral,
		CollateralType: collateralType,
		InterestRate:   interestRate,
		StartDate:      startDate,
		EndDate:        endDate,
		Status:         "Active",
		Repayments:     []Repayment{},
	}

	slm.Loans = append(slm.Loans, loan)

	err := smartcontracts.CreateLoanContract(loanID, borrowerID, amount, interestRate, startDate, endDate, collateral, collateralType)
	if err != nil {
		return "", err
	}

	notifications.SendNotification(borrowerID, "Secured Loan Created", "Your secured loan has been created and is now active.")
	return loanID, nil
}

// MakeRepayment allows a borrower to make a repayment on a secured loan
func (slm *SecuredLoanManagement) MakeRepayment(loanID string, amount float64) (string, error) {
	for i, loan := range slm.Loans {
		if loan.LoanID == loanID {
			if loan.Status != "Active" {
				return "", errors.New("loan is not active")
			}

			repaymentID := utils.GenerateID()
			repayment := Repayment{
				RepaymentID: repaymentID,
				Amount:      amount,
				Date:        time.Now(),
				Status:      "Completed",
			}

			slm.Loans[i].Repayments = append(slm.Loans[i].Repayments, repayment)
			slm.Loans[i].Amount -= amount

			if slm.Loans[i].Amount <= 0 {
				slm.Loans[i].Status = "Completed"
				notifications.SendNotification(loan.BorrowerID, "Loan Fully Repaid", "Congratulations! Your secured loan has been fully repaid.")
			} else {
				notifications.SendNotification(loan.BorrowerID, "Repayment Received", "Your repayment has been received. Remaining balance: "+fmt.Sprintf("%.2f", slm.Loans[i].Amount))
			}

			return repaymentID, nil
		}
	}
	return "", errors.New("loan not found")
}

// LiquidateCollateral liquidates the collateral of a defaulted loan
func (slm *SecuredLoanManagement) LiquidateCollateral(loanID string) error {
	for i, loan := range slm.Loans {
		if loan.LoanID == loanID {
			if loan.Status != "Defaulted" {
				return errors.New("loan is not defaulted")
			}

			err := smartcontracts.LiquidateCollateral(loan.Collateral, loan.CollateralType)
			if err != nil {
				return err
			}

			slm.Loans[i].Status = "Liquidated"
			notifications.SendNotification(loan.BorrowerID, "Collateral Liquidated", "Your collateral has been liquidated to cover the outstanding loan balance.")
			return nil
		}
	}
	return errors.New("loan not found")
}

// CheckLoanStatus checks the status of a loan
func (slm *SecuredLoanManagement) CheckLoanStatus(loanID string) (string, error) {
	for _, loan := range slm.Loans {
		if loan.LoanID == loanID {
			return loan.Status, nil
		}
	}
	return "", errors.New("loan not found")
}

// ListLoans lists all secured loans
func (slm *SecuredLoanManagement) ListLoans() []SecuredLoan {
	return slm.Loans
}

// DefaultLoan marks a loan as defaulted
func (slm *SecuredLoanManagement) DefaultLoan(loanID string) error {
	for i, loan := range slm.Loans {
		if loan.LoanID == loanID {
			if loan.Status != "Active" {
				return errors.New("only active loans can be defaulted")
			}

			slm.Loans[i].Status = "Defaulted"
			notifications.SendNotification(loan.BorrowerID, "Loan Defaulted", "Your loan has been marked as defaulted due to non-payment.")
			return nil
		}
	}
	return errors.New("loan not found")
}

// NewSmallBusinessGrantManager initializes a new SmallBusinessGrantManager instance.
func NewSmallBusinessGrantManager() *SmallBusinessGrantManager {
	return &SmallBusinessGrantManager{
		grants:  make(map[string]*SmallBusinessGrant),
		reports: make(map[string][]ProgressReport),
	}
}

// SubmitGrantProposal allows a user to submit a proposal for a small business grant.
func (sbm *SmallBusinessGrantManager) SubmitGrantProposal(applicantID, businessName, purpose string, amount float64) (string, error) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	grantID := generateID()
	grant := &SmallBusinessGrant{
		ID:             grantID,
		ApplicantID:    applicantID,
		BusinessName:   businessName,
		Amount:         amount,
		Purpose:        purpose,
		Status:         "Submitted",
		SubmissionDate: time.Now(),
	}

	sbm.grants[grantID] = grant
	return grantID, nil
}

// ApproveGrantProposal approves a submitted grant proposal.
func (sbm *SmallBusinessGrantManager) ApproveGrantProposal(grantID string) error {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	grant, exists := sbm.grants[grantID]
	if !exists {
		return errors.New("grant not found")
	}

	if grant.Status != "Submitted" {
		return errors.New("grant cannot be approved in its current status")
	}

	now := time.Now()
	grant.Status = "Approved"
	grant.ApprovalDate = &now
	return nil
}

// DisburseGrant disburses the approved grant to the applicant.
func (sbm *SmallBusinessGrantManager) DisburseGrant(grantID string) error {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	grant, exists := sbm.grants[grantID]
	if !exists {
		return errors.New("grant not found")
	}

	if grant.Status != "Approved" {
		return errors.New("grant cannot be disbursed in its current status")
	}

	now := time.Now()
	grant.Status = "Disbursed"
	grant.DisbursementDate = &now
	return nil
}

// SubmitProgressReport allows an applicant to submit a progress report on the grant usage.
func (sbm *SmallBusinessGrantManager) SubmitProgressReport(grantID, content string) (string, error) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	grant, exists := sbm.grants[grantID]
	if !exists {
		return "", errors.New("grant not found")
	}

	if grant.Status != "Disbursed" {
		return "", errors.New("progress reports can only be submitted for disbursed grants")
	}

	reportID := generateID()
	report := ProgressReport{
		ID:         reportID,
		GrantID:    grantID,
		ReportDate: time.Now(),
		Content:    content,
	}

	sbm.reports[grantID] = append(sbm.reports[grantID], report)
	grant.Reports = append(grant.Reports, report)
	return reportID, nil
}

// ReviewProgressReports reviews the submitted progress reports for a grant.
func (sbm *SmallBusinessGrantManager) ReviewProgressReports(grantID string) ([]ProgressReport, error) {
	sbm.mu.Lock()
	defer sbm.mu.Unlock()

	reports, exists := sbm.reports[grantID]
	if !exists {
		return nil, errors.New("no reports found for the specified grant")
	}

	return reports, nil
}

// generateID generates a unique ID for grants and reports.
func generateID() string {
	// Implementation of unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}

const (
	Pending   common.GrantStatus = "Pending"
	Approved  GrantStatus = "Approved"
	Rejected  GrantStatus = "Rejected"
)

// NewEcosystemGrant creates a new EcosystemGrantType.
func NewEcosystemGrant(applicant identity.User, proposal Proposal, amount *big.Int) *EcosystemGrantType {
	return &EcosystemGrantType{
		ID:          crypto.GenerateID(),
		Applicant:   applicant,
		Proposal:    proposal,
		Amount:      amount,
		Status:      Pending,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ApprovedBy:  []identity.Node{},
	}
}

// SubmitProposal submits a new proposal for voting.
func (g *EcosystemGrantType) SubmitProposal() error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.Status != Pending {
		return errors.New("proposal already processed")
	}

	vote := voting.NewVote(g.ID, g.Proposal.Title, g.Proposal.Description, g.Proposal.Justification, g.Proposal.RequestedAmount.String())
	err := voting.SubmitVote(vote)
	if err != nil {
		return err
	}
	
	g.UpdatedAt = time.Now()
	logger.Info("Proposal submitted successfully: ", g.Proposal.Title)
	return nil
}

// ApproveProposal approves the proposal by a node.
func (g *EcosystemGrantType) ApproveProposal(node identity.Node) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.Status != Pending {
		return errors.New("proposal already processed")
	}

	g.ApprovedBy = append(g.ApprovedBy, node)
	if len(g.ApprovedBy) >= 3 { // Assuming 3 approvals required
		g.Status = Approved
		g.UpdatedAt = time.Now()
		go g.disburseFunds()
		logger.Info("Proposal approved: ", g.Proposal.Title)
	}
	return nil
}

// RejectProposal rejects the proposal.
func (g *EcosystemGrantType) RejectProposal() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.Status = Rejected
	g.UpdatedAt = time.Now()
	logger.Info("Proposal rejected: ", g.Proposal.Title)
}

// disburseFunds disburses the grant funds to the applicant.
func (g *EcosystemGrantType) disburseFunds() {
	wallet := wallet.GetWallet(g.Applicant.ID)
	if wallet == nil {
		logger.Error("Wallet not found for applicant: ", g.Applicant.ID)
		return
	}

	err := wallet.Credit(g.Amount)
	if err != nil {
		logger.Error("Failed to disburse funds: ", err)
		return
	}
	
	logger.Info("Funds disbursed to applicant: ", g.Applicant.ID)
}

// GetGrantDetails returns the details of the grant.
func (g *EcosystemGrantType) GetGrantDetails() *EcosystemGrantType {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g
}

// ValidateProposal ensures the proposal meets all requirements.
func (g *EcosystemGrantType) ValidateProposal() error {
	if g.Proposal.Title == "" || g.Proposal.Description == "" || g.Proposal.Justification == "" || g.Proposal.RequestedAmount == nil {
		return errors.New("invalid proposal details")
	}
	return nil
}

// MonitorProgress monitors the progress of the funded project.
func (g *EcosystemGrantType) MonitorProgress() {
	// Implementation for monitoring the progress of the project funded by the grant
	// This could involve periodic reports from the applicant, milestone tracking, etc.
}

// GenerateProgressReport generates a progress report for the grant.
func (g *EcosystemGrantType) GenerateProgressReport() {
	// Implementation for generating a progress report
	// This could involve summarizing milestones achieved, funds utilized, etc.
}

func (g *EcosystemGrantType) initiateAIProposalReview() {
	// Implementation for AI-driven proposal review based on urgency and impact
	// Use machine learning models to evaluate and prioritize proposals
}

// NotifyUsers sends notifications to relevant users about the status of the grant.
func (g *EcosystemGrantType) NotifyUsers() {
	// Implementation for notifying users about the status of the grant
	// This could involve sending emails, SMS, or in-app notifications
}

// ValidateProposalAmount validates the requested amount against available funds.
func (g *EcosystemGrantType) ValidateProposalAmount() error {
	availableFunds := core.GetAvailableFunds()
	if g.Proposal.RequestedAmount.Cmp(availableFunds) == 1 {
		return errors.New("requested amount exceeds available funds")
	}
	return nil
}

// AuthorizeNodes verifies that the approving nodes are authorized to approve proposals.
func (g *EcosystemGrantType) AuthorizeNodes(nodes []identity.Node) error {
	for _, node := range nodes {
		if !node.IsAuthorized() {
			return errors.New("unauthorized node: " + node.ID)
		}
	}
	return nil
}

const (
	Pending   common.LoanStatus = "Pending"
	Approved  LoanStatus = "Approved"
	Rejected  LoanStatus = "Rejected"
	Disbursed LoanStatus = "Disbursed"
)

// NewUnsecuredLoan creates a new UnsecuredLoanType.
func NewUnsecuredLoan(borrower identity.User, proposal Proposal, amount *big.Int, interestRate float64, repaymentTerms RepaymentTerms) *UnsecuredLoanType {
	return &UnsecuredLoanType{
		ID:             crypto.GenerateID(),
		Borrower:       borrower,
		Proposal:       proposal,
		Amount:         amount,
		InterestRate:   interestRate,
		RepaymentTerms: repaymentTerms,
		Status:         Pending,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		ApprovedBy:     []identity.Node{},
	}
}

// SubmitProposal submits a new loan proposal for voting.
func (u *UnsecuredLoanType) SubmitProposal() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.Status != Pending {
		return errors.New("proposal already processed")
	}

	vote := voting.NewVote(u.ID, u.Proposal.Title, u.Proposal.Description, u.Proposal.Justification, u.Proposal.RequestedAmount.String())
	err := voting.SubmitVote(vote)
	if err != nil {
		return err
	}

	u.UpdatedAt = time.Now()
	logger.Info("Loan proposal submitted successfully: ", u.Proposal.Title)
	return nil
}

// ApproveProposal approves the loan proposal by a node.
func (u *UnsecuredLoanType) ApproveProposal(node identity.Node) error {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.Status != Pending {
		return errors.New("proposal already processed")
	}

	if err := u.authorizeNode(node); err != nil {
		return err
	}

	u.ApprovedBy = append(u.ApprovedBy, node)
	if len(u.ApprovedBy) >= 3 { // Assuming 3 approvals required
		u.Status = Approved
		u.UpdatedAt = time.Now()
		logger.Info("Loan proposal approved: ", u.Proposal.Title)
		go u.disburseFunds()
	}
	return nil
}

// RejectProposal rejects the loan proposal.
func (u *UnsecuredLoanType) RejectProposal() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	u.Status = Rejected
	u.UpdatedAt = time.Now()
	logger.Info("Loan proposal rejected: ", u.Proposal.Title)
}

// disburseFunds disburses the loan funds to the borrower.
func (u *UnsecuredLoanType) disburseFunds() {
	wallet := wallet.GetWallet(u.Borrower.ID)
	if wallet == nil {
		logger.Error("Wallet not found for borrower: ", u.Borrower.ID)
		return
	}

	err := wallet.Credit(u.Amount)
	if err != nil {
		logger.Error("Failed to disburse funds: ", err)
		return
	}

	u.Status = Disbursed
	u.UpdatedAt = time.Now()
	logger.Info("Funds disbursed to borrower: ", u.Borrower.ID)
}

// GetLoanDetails returns the details of the loan.
func (u *UnsecuredLoanType) GetLoanDetails() *UnsecuredLoanType {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	return u
}

// ValidateProposal ensures the proposal meets all requirements.
func (u *UnsecuredLoanType) ValidateProposal() error {
	if u.Proposal.Title == "" || u.Proposal.Description == "" || u.Proposal.Justification == "" || u.Proposal.RequestedAmount == nil {
		return errors.New("invalid proposal details")
	}
	return nil
}

// MonitorRepayment monitors the repayment of the loan.
func (u *UnsecuredLoanType) MonitorRepayment() {
	// Implementation for monitoring the repayment of the loan
	// This could involve periodic payment tracking, notifications for due payments, etc.
}

// GenerateRepaymentSchedule generates a repayment schedule for the loan.
func (u *UnsecuredLoanType) GenerateRepaymentSchedule() {
	// Implementation for generating a repayment schedule
	// This could involve calculating monthly/quarterly/annual payments based on the amount and interest rate
}

func (u *UnsecuredLoanType) authorizeNode(node identity.Node) error {
	if !node.IsAuthorized() {
		return errors.New("unauthorized node: " + node.ID)
	}
	return nil
}

// NotifyUsers sends notifications to relevant users about the status of the loan.
func (u *UnsecuredLoanType) NotifyUsers() {
	// Implementation for notifying users about the status of the loan
	// This could involve sending emails, SMS, or in-app notifications
}

// ValidateLoanAmount validates the requested loan amount against available funds.
func (u *UnsecuredLoanType) ValidateLoanAmount() error {
	availableFunds := core.GetAvailableFunds()
	if u.Proposal.RequestedAmount.Cmp(availableFunds) == 1 {
		return errors.New("requested amount exceeds available funds")
	}
	return nil
}

// FraudDetection detects potential fraud in the loan application process.
func (u *UnsecuredLoanType) FraudDetection() {
	// Implementation for detecting potential fraud
	// This could involve analyzing borrower history, behavior, and other risk factors
}

// RecordTransaction records the loan transaction on the blockchain.
func (u *UnsecuredLoanType) RecordTransaction() {
	// Implementation for recording the transaction on the blockchain
	// This ensures transparency and immutability of the loan transaction
}

// ApplyPenalty applies penalties for late repayments.
func (u *UnsecuredLoanType) ApplyPenalty() {
	// Implementation for applying penalties for late repayments
	// This could involve calculating and adding late fees to the repayment schedule
}

// GetRepaymentStatus returns the current status of loan repayment.
func (u *UnsecuredLoanType) GetRepaymentStatus() string {
	// Implementation for retrieving the current status of the loan repayment
	// This could involve checking the remaining balance, due dates, etc.
	return ""
}

// ReassessLoanTerms allows reassessment of loan terms if needed.
func (u *UnsecuredLoanType) ReassessLoanTerms() {
	// Implementation for reassessing loan terms
	// This could involve modifying the interest rate, repayment schedule, etc. based on new conditions
}
