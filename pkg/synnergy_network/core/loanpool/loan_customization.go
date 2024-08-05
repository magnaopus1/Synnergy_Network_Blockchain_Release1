package loan_customization

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/blockchain"
	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/models"
	"github.com/synnergy_network/utils"
)

// NewCustomizableLoanTerms creates a new instance of the CustomizableLoanTerms.
func NewCustomizableLoanTerms(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *CustomizableLoanTerms {
	return &CustomizableLoanTerms{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// ProposeLoanTerms allows borrowers to propose custom loan terms.
func (clt *CustomizableLoanTerms) ProposeLoanTerms(borrowerID string, amount float64, duration time.Duration, repaymentSchedule string, interestRate float64, collateral models.Collateral) (string, error) {
	if amount <= 0 {
		return "", errors.New("loan amount must be greater than zero")
	}

	if duration <= 0 {
		return "", errors.New("loan duration must be greater than zero")
	}

	if interestRate < 0 {
		return "", errors.New("interest rate cannot be negative")
	}

	proposalID := utils.GenerateUUID()
	proposal := models.LoanProposal{
		ID:              proposalID,
		BorrowerID:      borrowerID,
		Amount:          amount,
		Duration:        duration,
		RepaymentSchedule: repaymentSchedule,
		InterestRate:    interestRate,
		Collateral:      collateral,
		Status:          models.ProposalStatusPending,
		SubmittedAt:     time.Now(),
	}

	err := clt.blockchain.AddProposal(proposal)
	if err != nil {
		return "", err
	}

	return proposalID, nil
}

// ApproveLoanTerms allows authority nodes to approve proposed loan terms.
func (clt *CustomizableLoanTerms) ApproveLoanTerms(proposalID string, authorityNodeID string) error {
	proposal, err := clt.blockchain.GetProposal(proposalID)
	if err != nil {
		return err
	}

	if proposal.Status != models.ProposalStatusPending {
		return errors.New("proposal is not in pending status")
	}

	proposal.ApprovedBy = append(proposal.ApprovedBy, authorityNodeID)
	if len(proposal.ApprovedBy) >= 3 {
		proposal.Status = models.ProposalStatusApproved
	}

	return clt.blockchain.UpdateProposal(proposal)
}

// DisburseLoan disburses funds to the borrower for an approved loan.
func (clt *CustomizableLoanTerms) DisburseLoan(proposalID string) error {
	proposal, err := clt.blockchain.GetProposal(proposalID)
	if err != nil {
		return err
	}

	if proposal.Status != models.ProposalStatusApproved {
		return errors.New("proposal is not approved")
	}

	loanTokenID := utils.GenerateUUID()
	loanToken := models.LoanToken{
		ID:         loanTokenID,
		ProposalID: proposalID,
		Amount:     proposal.Amount,
		BorrowerID: proposal.BorrowerID,
		IssuedAt:   time.Now(),
	}

	err = clt.blockchain.IssueLoanToken(loanToken)
	if err != nil {
		return err
	}

	err = clt.blockchain.TransferFunds("loan_pool", proposal.BorrowerID, proposal.Amount)
	if err != nil {
		return err
	}

	proposal.Status = models.ProposalStatusDisbursed
	return clt.blockchain.UpdateProposal(proposal)
}

// AdjustLoanTerms allows borrowers to request adjustments to their loan terms.
func (clt *CustomizableLoanTerms) AdjustLoanTerms(proposalID string, newAmount float64, newDuration time.Duration, newRepaymentSchedule string, newInterestRate float64) error {
	proposal, err := clt.blockchain.GetProposal(proposalID)
	if err != nil {
		return err
	}

	if proposal.Status != models.ProposalStatusDisbursed {
		return errors.New("loan terms can only be adjusted for disbursed loans")
	}

	proposal.Amount = newAmount
	proposal.Duration = newDuration
	proposal.RepaymentSchedule = newRepaymentSchedule
	proposal.InterestRate = newInterestRate

	return clt.blockchain.UpdateProposal(proposal)
}

// RepayLoan processes the repayment of the loan by the borrower.
func (clt *CustomizableLoanTerms) RepayLoan(loanTokenID string, amount float64) error {
	loanToken, err := clt.blockchain.GetLoanToken(loanTokenID)
	if err != nil {
		return err
	}

	if loanToken.RepaidAmount+amount > loanToken.Amount {
		return errors.New("repayment amount exceeds loan amount")
	}

	err = clt.blockchain.TransferFunds(loanToken.BorrowerID, "loan_pool", amount)
	if err != nil {
		return err
	}

	loanToken.RepaidAmount += amount
	if loanToken.RepaidAmount == loanToken.Amount {
		loanToken.Status = models.LoanTokenStatusRepaid
	}

	return clt.blockchain.UpdateLoanToken(loanToken)
}

// MonitorLoan ensures timely repayment and detects potential defaults.
func (clt *CustomizableLoanTerms) MonitorLoan() {
	loanTokens := clt.blockchain.GetAllLoanTokens()
	for _, loanToken := range loanTokens {
		if loanToken.Status == models.LoanTokenStatusRepaid || loanToken.Status == models.LoanTokenStatusDefaulted {
			continue
		}

		if time.Since(loanToken.IssuedAt) > loanToken.Duration {
			if loanToken.RepaidAmount < loanToken.Amount {
				loanToken.Status = models.LoanTokenStatusDefaulted
				clt.blockchain.UpdateLoanToken(loanToken)
				// Additional logic for handling defaults can be added here
			}
		}
	}
}

// SendRepaymentReminder sends reminders to borrowers for upcoming repayments.
func (clt *CustomizableLoanTerms) SendRepaymentReminder(borrowerID string, loanTokenID string) error {
	loanToken, err := clt.blockchain.GetLoanToken(loanTokenID)
	if err != nil {
		return err
	}

	dueDate := loanToken.IssuedAt.Add(loanToken.Duration / 2)
	if time.Until(dueDate) < 7*24*time.Hour {
		// Send reminder
		message := fmt.Sprintf("Dear %s, your loan repayment is due in 7 days. Please ensure you have sufficient funds.", borrowerID)
		return utils.SendNotification(borrowerID, message)
	}

	return nil
}

// ApplyPenalty applies a penalty to the borrower for late repayment.
func (clt *CustomizableLoanTerms) ApplyPenalty(loanTokenID string, penaltyAmount float64) error {
	loanToken, err := clt.blockchain.GetLoanToken(loanTokenID)
	if err != nil {
		return err
	}

	if loanToken.RepaidAmount < loanToken.Amount && loanToken.Status != models.LoanTokenStatusDefaulted {
		loanToken.Penalties += penaltyAmount
		return clt.blockchain.UpdateLoanToken(loanToken)
	}

	return errors.New("cannot apply penalty to repaid or defaulted loan")
}

// GetLoanStatus retrieves the status of a specific loan.
func (clt *CustomizableLoanTerms) GetLoanStatus(loanTokenID string) (models.LoanTokenStatus, error) {
	loanToken, err := clt.blockchain.GetLoanToken(loanTokenID)
	if err != nil {
		return "", err
	}
	return loanToken.Status, nil
}

// NewDynamicInterestRates creates a new instance of DynamicInterestRates.
func NewDynamicInterestRates(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *DynamicInterestRates {
	return &DynamicInterestRates{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// AdjustInterestRate dynamically adjusts the interest rate based on various factors.
func (dir *DynamicInterestRates) AdjustInterestRate(loanID string) error {
	loan, err := dir.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	creditScore, err := dir.getCreditScore(loan.BorrowerID)
	if err != nil {
		return err
	}

	marketRate := dir.getMarketRate()
	borrowerRisk := dir.calculateRiskFactor(creditScore)
	newInterestRate := marketRate + borrowerRisk

	loan.InterestRate = newInterestRate
	return dir.blockchain.UpdateLoan(loan)
}

// getCreditScore retrieves the credit score of the borrower.
func (dir *DynamicInterestRates) getCreditScore(borrowerID string) (float64, error) {
	creditScore, err := dir.blockchain.GetCreditScore(borrowerID)
	if err != nil {
		return 0, err
	}
	return creditScore, nil
}

// getMarketRate retrieves the current market interest rate.
func (dir *DynamicInterestRates) getMarketRate() float64 {
	// Assuming an external service or API provides the current market rate
	// Here we just return a fixed value for simplicity
	return 3.5 // Example market rate
}

// calculateRiskFactor calculates the risk factor based on the borrower's credit score.
func (dir *DynamicInterestRates) calculateRiskFactor(creditScore float64) float64 {
	// Example calculation: the riskier the borrower, the higher the risk factor
	return math.Max(0, (700-creditScore)/100)
}

// ApplyInterest calculates the interest for a given amount and duration.
func (dir *DynamicInterestRates) ApplyInterest(amount float64, duration time.Duration, interestRate float64) float64 {
	years := duration.Hours() / 24 / 365
	return amount * math.Pow(1+interestRate/100, years)
}

// MonitorRates monitors the interest rates and adjusts them periodically.
func (dir *DynamicInterestRates) MonitorRates() {
	loans := dir.blockchain.GetAllLoans()
	for _, loan := range loans {
		if loan.Status == models.LoanStatusActive {
			err := dir.AdjustInterestRate(loan.ID)
			if err != nil {
				fmt.Printf("Error adjusting interest rate for loan %s: %v\n", loan.ID, err)
			}
		}
	}
}

// NotifyRateChange notifies the borrower of any changes in the interest rate.
func (dir *DynamicInterestRates) NotifyRateChange(borrowerID string, newRate float64) error {
	message := fmt.Sprintf("Dear %s, your loan interest rate has been adjusted to %.2f%%", borrowerID, newRate)
	return utils.SendNotification(borrowerID, message)
}

// GetInterestRate returns the current interest rate for a specific loan.
func (dir *DynamicInterestRates) GetInterestRate(loanID string) (float64, error) {
	loan, err := dir.blockchain.GetLoan(loanID)
	if err != nil {
		return 0, err
	}
	return loan.InterestRate, nil
}

// PredictFutureRate uses predictive analytics to forecast future interest rates.
func (dir *DynamicInterestRates) PredictFutureRate(loanID string) (float64, error) {
	loan, err := dir.blockchain.GetLoan(loanID)
	if err != nil {
		return 0, err
	}

	creditScore, err := dir.getCreditScore(loan.BorrowerID)
	if err != nil {
		return 0, err
	}

	// Example predictive analysis: Adjust future rates based on historical trends
	historicalRates := dir.blockchain.GetHistoricalRates(loan.BorrowerID)
	trend := dir.analyzeTrends(historicalRates)

	marketRate := dir.getMarketRate()
	borrowerRisk := dir.calculateRiskFactor(creditScore)
	futureRate := marketRate + borrowerRisk + trend

	return futureRate, nil
}

// analyzeTrends analyzes historical interest rates to find trends.
func (dir *DynamicInterestRates) analyzeTrends(historicalRates []float64) float64 {
	// Simple trend analysis example: Calculate the average change in rates
	if len(historicalRates) < 2 {
		return 0
	}

	totalChange := 0.0
	for i := 1; i < len(historicalRates); i++ {
		totalChange += historicalRates[i] - historicalRates[i-1]
	}

	return totalChange / float64(len(historicalRates)-1)
}


// NewFlexibleRepaymentOptions creates a new instance of FlexibleRepaymentOptions.
func NewFlexibleRepaymentOptions(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *FlexibleRepaymentOptions {
	return &FlexibleRepaymentOptions{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// ProposeRepaymentPlan allows borrowers to propose a customized repayment plan.
func (fro *FlexibleRepaymentOptions) ProposeRepaymentPlan(borrowerID string, loanID string, repaymentSchedule string, additionalTerms map[string]string) (string, error) {
	loan, err := fro.blockchain.GetLoan(loanID)
	if err != nil {
		return "", err
	}

	if loan.BorrowerID != borrowerID {
		return "", errors.New("borrower ID does not match loan")
	}

	repaymentPlanID := utils.GenerateUUID()
	repaymentPlan := models.RepaymentPlan{
		ID:               repaymentPlanID,
		LoanID:           loanID,
		BorrowerID:       borrowerID,
		RepaymentSchedule: repaymentSchedule,
		AdditionalTerms:  additionalTerms,
		Status:           models.PlanStatusPending,
		SubmittedAt:      time.Now(),
	}

	err = fro.blockchain.AddRepaymentPlan(repaymentPlan)
	if err != nil {
		return "", err
	}

	return repaymentPlanID, nil
}

// ApproveRepaymentPlan allows authority nodes to approve a proposed repayment plan.
func (fro *FlexibleRepaymentOptions) ApproveRepaymentPlan(planID string, authorityNodeID string) error {
	repaymentPlan, err := fro.blockchain.GetRepaymentPlan(planID)
	if err != nil {
		return err
	}

	if repaymentPlan.Status != models.PlanStatusPending {
		return errors.New("repayment plan is not in pending status")
	}

	repaymentPlan.ApprovedBy = append(repaymentPlan.ApprovedBy, authorityNodeID)
	if len(repaymentPlan.ApprovedBy) >= 3 {
		repaymentPlan.Status = models.PlanStatusApproved
	}

	return fro.blockchain.UpdateRepaymentPlan(repaymentPlan)
}

// AdjustRepaymentPlan allows borrowers to request adjustments to their repayment plans.
func (fro *FlexibleRepaymentOptions) AdjustRepaymentPlan(planID string, newRepaymentSchedule string, newAdditionalTerms map[string]string) error {
	repaymentPlan, err := fro.blockchain.GetRepaymentPlan(planID)
	if err != nil {
		return err
	}

	if repaymentPlan.Status != models.PlanStatusApproved {
		return errors.New("repayment plan can only be adjusted for approved plans")
	}

	repaymentPlan.RepaymentSchedule = newRepaymentSchedule
	repaymentPlan.AdditionalTerms = newAdditionalTerms

	return fro.blockchain.UpdateRepaymentPlan(repaymentPlan)
}

// ProcessRepayment processes the repayment of the loan by the borrower according to the approved plan.
func (fro *FlexibleRepaymentOptions) ProcessRepayment(loanID string, amount float64) error {
	loan, err := fro.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	repaymentPlan, err := fro.blockchain.GetRepaymentPlanByLoanID(loanID)
	if err != nil {
		return err
	}

	if loan.RepaidAmount+amount > loan.Amount {
		return errors.New("repayment amount exceeds loan amount")
	}

	err = fro.blockchain.TransferFunds(loan.BorrowerID, "loan_pool", amount)
	if err != nil {
		return err
	}

	loan.RepaidAmount += amount
	if loan.RepaidAmount == loan.Amount {
		loan.Status = models.LoanStatusRepaid
		repaymentPlan.Status = models.PlanStatusCompleted
	}

	return fro.blockchain.UpdateLoan(loan)
}

// MonitorRepayments ensures timely repayment and detects potential defaults.
func (fro *FlexibleRepaymentOptions) MonitorRepayments() {
	loans := fro.blockchain.GetAllLoans()
	for _, loan := range loans {
		if loan.Status == models.LoanStatusRepaid || loan.Status == models.LoanStatusDefaulted {
			continue
		}

		repaymentPlan, err := fro.blockchain.GetRepaymentPlanByLoanID(loan.ID)
		if err != nil {
			fmt.Printf("Error getting repayment plan for loan %s: %v\n", loan.ID, err)
			continue
		}

		// Additional monitoring logic to check if repayments are on track
		// and trigger notifications or penalties as necessary
	}
}

// SendRepaymentReminder sends reminders to borrowers for upcoming repayments.
func (fro *FlexibleRepaymentOptions) SendRepaymentReminder(borrowerID string, loanID string) error {
	loan, err := fro.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	repaymentPlan, err := fro.blockchain.GetRepaymentPlanByLoanID(loanID)
	if err != nil {
		return err
	}

	// Assuming repaymentSchedule is a string that can be parsed into a time.Duration
	dueDate := loan.IssuedAt.Add(parseDuration(repaymentPlan.RepaymentSchedule) / 2)
	if time.Until(dueDate) < 7*24*time.Hour {
		// Send reminder
		message := fmt.Sprintf("Dear %s, your loan repayment is due in 7 days. Please ensure you have sufficient funds.", borrowerID)
		return utils.SendNotification(borrowerID, message)
	}

	return nil
}

// ApplyPenalty applies a penalty to the borrower for late repayment.
func (fro *FlexibleRepaymentOptions) ApplyPenalty(loanID string, penaltyAmount float64) error {
	loan, err := fro.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	if loan.RepaidAmount < loan.Amount && loan.Status != models.LoanStatusDefaulted {
		loan.Penalties += penaltyAmount
		return fro.blockchain.UpdateLoan(loan)
	}

	return errors.New("cannot apply penalty to repaid or defaulted loan")
}

// GetRepaymentStatus retrieves the status of a specific repayment plan.
func (fro *FlexibleRepaymentOptions) GetRepaymentStatus(planID string) (models.PlanStatus, error) {
	repaymentPlan, err := fro.blockchain.GetRepaymentPlan(planID)
	if err != nil {
		return "", err
	}
	return repaymentPlan.Status, nil
}

// parseDuration is a helper function to parse repayment schedule string into time.Duration
func parseDuration(schedule string) time.Duration {
	// Implement parsing logic based on the format of repaymentSchedule
	// This is a placeholder implementation
	return time.Hour * 24 * 30 // Assume monthly repayments for simplicity
}


// NewLoanTermsAudits creates a new instance of LoanTermsAudits.
func NewLoanTermsAudits(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *LoanTermsAudits {
	return &LoanTermsAudits{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// ScheduleAudit schedules a regular audit for a loan term.
func (lta *LoanTermsAudits) ScheduleAudit(loanID string, interval time.Duration) error {
	auditID := utils.GenerateUUID()
	audit := models.LoanAudit{
		ID:        auditID,
		LoanID:    loanID,
		Scheduled: time.Now().Add(interval),
		Status:    models.AuditStatusScheduled,
	}

	err := lta.blockchain.AddAudit(audit)
	if err != nil {
		return err
	}

	return nil
}

// PerformAudit performs the actual audit on the specified loan term.
func (lta *LoanTermsAudits) PerformAudit(auditID string) error {
	audit, err := lta.blockchain.GetAudit(auditID)
	if err != nil {
		return err
	}

	loan, err := lta.blockchain.GetLoan(audit.LoanID)
	if err != nil {
		return err
	}

	// Perform the audit
	if err := lta.validateLoanTerms(loan); err != nil {
		audit.Status = models.AuditStatusFailed
		audit.Notes = err.Error()
	} else {
		audit.Status = models.AuditStatusPassed
		audit.Notes = "Audit passed successfully"
	}

	audit.PerformedAt = time.Now()
	return lta.blockchain.UpdateAudit(audit)
}

// validateLoanTerms validates the terms and conditions of the loan.
func (lta *LoanTermsAudits) validateLoanTerms(loan models.Loan) error {
	if loan.Amount <= 0 {
		return errors.New("loan amount must be greater than zero")
	}
	if loan.Duration <= 0 {
		return errors.New("loan duration must be greater than zero")
	}
	if loan.InterestRate < 0 {
		return errors.New("interest rate cannot be negative")
	}
	if loan.BorrowerID == "" {
		return errors.New("borrower ID cannot be empty")
	}

	// Additional validation checks can be added here

	return nil
}

// MonitorAudits continuously monitors and triggers scheduled audits.
func (lta *LoanTermsAudits) MonitorAudits() {
	for {
		audits := lta.blockchain.GetAllScheduledAudits()
		for _, audit := range audits {
			if time.Now().After(audit.Scheduled) {
				err := lta.PerformAudit(audit.ID)
				if err != nil {
					// Log or handle the error as needed
					continue
				}
			}
		}
		time.Sleep(1 * time.Hour) // Check every hour; adjust as needed
	}
}

// AuditHistory retrieves the audit history for a specific loan.
func (lta *LoanTermsAudits) AuditHistory(loanID string) ([]models.LoanAudit, error) {
	return lta.blockchain.GetAuditHistory(loanID)
}

// ReportAuditIssues reports any issues found during the audit.
func (lta *LoanTermsAudits) ReportAuditIssues(auditID string, issues []string) error {
	audit, err := lta.blockchain.GetAudit(auditID)
	if err != nil {
		return err
	}

	audit.Status = models.AuditStatusIssuesFound
	audit.Notes = "Issues: " + strings.Join(issues, "; ")

	return lta.blockchain.UpdateAudit(audit)
}

// NotifyStakeholders sends notifications to stakeholders about audit results.
func (lta *LoanTermsAudits) NotifyStakeholders(auditID string) error {
	audit, err := lta.blockchain.GetAudit(auditID)
	if err != nil {
		return err
	}

	loan, err := lta.blockchain.GetLoan(audit.LoanID)
	if err != nil {
		return err
	}

	message := fmt.Sprintf("Audit for Loan ID %s: %s", loan.ID, audit.Notes)
	return utils.SendNotification(loan.BorrowerID, message)
}

// NewLoanTermsMonitoring creates a new instance of LoanTermsMonitoring.
func NewLoanTermsMonitoring(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *LoanTermsMonitoring {
	return &LoanTermsMonitoring{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// MonitorLoanTerms continuously monitors loans to ensure compliance with terms and conditions.
func (ltm *LoanTermsMonitoring) MonitorLoanTerms() {
	for {
		loans := ltm.blockchain.GetAllLoans()
		for _, loan := range loans {
			if err := ltm.checkCompliance(loan); err != nil {
				// Log or handle the error as needed
				fmt.Printf("Error checking compliance for loan %s: %v\n", loan.ID, err)
				continue
			}
		}
		time.Sleep(1 * time.Hour) // Adjust the frequency as needed
	}
}

// checkCompliance checks if a loan is compliant with its terms and conditions.
func (ltm *LoanTermsMonitoring) checkCompliance(loan models.Loan) error {
	if loan.Status == models.LoanStatusRepaid || loan.Status == models.LoanStatusDefaulted {
		return nil
	}

	// Check if the loan has reached its maturity date
	if time.Now().After(loan.IssuedAt.Add(loan.Duration)) {
		if loan.RepaidAmount < loan.Amount {
			loan.Status = models.LoanStatusDefaulted
			return ltm.blockchain.UpdateLoan(loan)
		}
	}

	// Additional compliance checks can be added here

	return nil
}

// AlertNonCompliance alerts borrowers and relevant stakeholders of non-compliance.
func (ltm *LoanTermsMonitoring) AlertNonCompliance(loanID string, issues []string) error {
	loan, err := ltm.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	message := fmt.Sprintf("Loan ID %s has the following compliance issues: %s", loanID, issues)
	return utils.SendNotification(loan.BorrowerID, message)
}

// GenerateComplianceReport generates a report of loan compliance status.
func (ltm *LoanTermsMonitoring) GenerateComplianceReport() ([]models.ComplianceReport, error) {
	var reports []models.ComplianceReport
	loans := ltm.blockchain.GetAllLoans()

	for _, loan := range loans {
		report := models.ComplianceReport{
			LoanID: loan.ID,
			Status: loan.Status,
		}

		if err := ltm.checkCompliance(loan); err != nil {
			report.Issues = append(report.Issues, err.Error())
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// NotifyStakeholders sends compliance reports to relevant stakeholders.
func (ltm *LoanTermsMonitoring) NotifyStakeholders() error {
	reports, err := ltm.GenerateComplianceReport()
	if err != nil {
		return err
	}

	for _, report := range reports {
		message := fmt.Sprintf("Compliance report for Loan ID %s: Status: %s, Issues: %v", report.LoanID, report.Status, report.Issues)
		if err := utils.SendNotification("stakeholder@example.com", message); err != nil {
			return err
		}
	}

	return nil
}

// ReviewLoanTerms allows authority nodes to review and update loan terms.
func (ltm *LoanTermsMonitoring) ReviewLoanTerms(loanID string, updatedTerms models.LoanTerms) error {
	loan, err := ltm.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	if loan.Status != models.LoanStatusDisbursed {
		return errors.New("only disbursed loans can have their terms reviewed")
	}

	loan.Terms = updatedTerms
	return ltm.blockchain.UpdateLoan(loan)
}

// SchedulePeriodicReviews schedules periodic reviews for loan compliance.
func (ltm *LoanTermsMonitoring) SchedulePeriodicReviews(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ltm.NotifyStakeholders(); err != nil {
				// Log or handle the error as needed
				fmt.Printf("Error notifying stakeholders: %v\n", err)
			}
		}
	}
}

// ApplyLoanModifications applies modifications to a loan based on compliance findings.
func (ltm *LoanTermsMonitoring) ApplyLoanModifications(loanID string, modifications models.LoanModifications) error {
	loan, err := ltm.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	if loan.Status != models.LoanStatusDisbursed {
		return errors.New("only disbursed loans can be modified")
	}

	if modifications.NewInterestRate != nil {
		loan.InterestRate = *modifications.NewInterestRate
	}

	if modifications.NewDuration != nil {
		loan.Duration = *modifications.NewDuration
	}

	if modifications.NewRepaymentSchedule != nil {
		loan.RepaymentSchedule = *modifications.NewRepaymentSchedule
	}

	return ltm.blockchain.UpdateLoan(loan)
}

// ResolveComplianceIssues resolves compliance issues for a loan.
func (ltm *LoanTermsMonitoring) ResolveComplianceIssues(loanID string, resolution models.ComplianceResolution) error {
	loan, err := ltm.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	loan.ComplianceIssues = resolution.Notes
	loan.Status = resolution.NewStatus

	return ltm.blockchain.UpdateLoan(loan)
}

// NewLoanTermsReporting creates a new instance of LoanTermsReporting.
func NewLoanTermsReporting(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *LoanTermsReporting {
	return &LoanTermsReporting{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// GenerateReport generates a comprehensive report on the terms and status of a specific loan.
func (ltr *LoanTermsReporting) GenerateReport(loanID string) (models.LoanReport, error) {
	loan, err := ltr.blockchain.GetLoan(loanID)
	if err != nil {
		return models.LoanReport{}, err
	}

	report := models.LoanReport{
		LoanID:          loan.ID,
		BorrowerID:      loan.BorrowerID,
		Amount:          loan.Amount,
		InterestRate:    loan.InterestRate,
		RepaymentPlan:   loan.RepaymentSchedule,
		RepaidAmount:    loan.RepaidAmount,
		Status:          loan.Status,
		Collateral:      loan.Collateral,
		IssuedAt:        loan.IssuedAt,
		DueDate:         loan.IssuedAt.Add(loan.Duration),
		ComplianceNotes: loan.ComplianceIssues,
	}

	return report, nil
}

// GenerateAggregateReport generates an aggregate report of all loans within the system.
func (ltr *LoanTermsReporting) GenerateAggregateReport() ([]models.LoanReport, error) {
	loans := ltr.blockchain.GetAllLoans()
	var reports []models.LoanReport

	for _, loan := range loans {
		report, err := ltr.GenerateReport(loan.ID)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}

// MonitorLoans continuously monitors loans and generates periodic reports.
func (ltr *LoanTermsReporting) MonitorLoans() {
	ticker := time.NewTicker(24 * time.Hour) // Adjust the frequency as needed
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			reports, err := ltr.GenerateAggregateReport()
			if err != nil {
				fmt.Printf("Error generating aggregate report: %v\n", err)
				continue
			}

			err = ltr.NotifyStakeholders(reports)
			if err != nil {
				fmt.Printf("Error notifying stakeholders: %v\n", err)
			}
		}
	}
}

// NotifyStakeholders sends the generated reports to relevant stakeholders.
func (ltr *LoanTermsReporting) NotifyStakeholders(reports []models.LoanReport) error {
	for _, report := range reports {
		message := fmt.Sprintf("Loan Report for Loan ID %s: Status: %s, Amount: %.2f, Repaid: %.2f, Due Date: %s, Compliance Issues: %s",
			report.LoanID, report.Status, report.Amount, report.RepaidAmount, report.DueDate.Format("2006-01-02"), report.ComplianceNotes)
		err := utils.SendNotification(report.BorrowerID, message)
		if err != nil {
			return err
		}
	}
	return nil
}

// ComplianceSummary generates a compliance summary for all loans.
func (ltr *LoanTermsReporting) ComplianceSummary() ([]models.ComplianceSummary, error) {
	loans := ltr.blockchain.GetAllLoans()
	var summaries []models.ComplianceSummary

	for _, loan := range loans {
		summary := models.ComplianceSummary{
			LoanID:    loan.ID,
			Status:    loan.Status,
			Compliance: loan.ComplianceIssues,
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// AuditReports conducts an audit of all loans and generates reports.
func (ltr *LoanTermsReporting) AuditReports() ([]models.LoanReport, error) {
	loans := ltr.blockchain.GetAllLoans()
	var reports []models.LoanReport

	for _, loan := range loans {
		if err := ltr.auditLoan(loan.ID); err != nil {
			return nil, err
		}
		report, err := ltr.GenerateReport(loan.ID)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}

	return reports, nil
}

// auditLoan performs an audit on a specific loan.
func (ltr *LoanTermsReporting) auditLoan(loanID string) error {
	loan, err := ltr.blockchain.GetLoan(loanID)
	if err != nil {
		return err
	}

	// Perform compliance checks and update loan status accordingly
	if loan.RepaidAmount < loan.Amount && time.Now().After(loan.IssuedAt.Add(loan.Duration)) {
		loan.Status = models.LoanStatusDefaulted
		loan.ComplianceIssues = "Loan has defaulted due to non-repayment."
	}

	return ltr.blockchain.UpdateLoan(loan)
}

// ExportReports exports the generated reports in a specified format (e.g., CSV, JSON).
func (ltr *LoanTermsReporting) ExportReports(format string, reports []models.LoanReport) (string, error) {
	switch format {
	case "CSV":
		return utils.ExportToCSV(reports)
	case "JSON":
		return utils.ExportToJSON(reports)
	default:
		return "", errors.New("unsupported export format")
	}
}

// GetLoanComplianceReport generates a compliance report for a specific loan.
func (ltr *LoanTermsReporting) GetLoanComplianceReport(loanID string) (models.ComplianceReport, error) {
	loan, err := ltr.blockchain.GetLoan(loanID)
	if err != nil {
		return models.ComplianceReport{}, err
	}

	complianceReport := models.ComplianceReport{
		LoanID:          loan.ID,
		Status:          loan.Status,
		ComplianceNotes: loan.ComplianceIssues,
	}

	return complianceReport, nil
}

// NewPersonalizedRecommendations creates a new instance of PersonalizedRecommendations.
func NewPersonalizedRecommendations(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *PersonalizedRecommendations {
	return &PersonalizedRecommendations{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// GenerateRecommendation generates a personalized loan recommendation for a user.
func (pr *PersonalizedRecommendations) GenerateRecommendation(userID string) (models.LoanRecommendation, error) {
	userProfile, err := pr.blockchain.GetUserProfile(userID)
	if err != nil {
		return models.LoanRecommendation{}, err
	}

	recommendation := pr.createRecommendation(userProfile)
	return recommendation, nil
}

// createRecommendation creates a loan recommendation based on the user's profile.
func (pr *PersonalizedRecommendations) createRecommendation(userProfile models.UserProfile) models.LoanRecommendation {
	// Implement logic to analyze user profile and generate recommendations
	// This is a simplified example, adjust based on actual requirements
	return models.LoanRecommendation{
		UserID:         userProfile.UserID,
		RecommendedAmount: pr.calculateRecommendedAmount(userProfile),
		RecommendedTerms:  pr.suggestTerms(userProfile),
		CreatedAt:         time.Now(),
	}
}

// calculateRecommendedAmount calculates the recommended loan amount based on the user's profile.
func (pr *PersonalizedRecommendations) calculateRecommendedAmount(userProfile models.UserProfile) float64 {
	// Implement a detailed algorithm to calculate the recommended amount
	return userProfile.AnnualIncome * 0.2 // Example calculation
}

// suggestTerms suggests loan terms based on the user's profile.
func (pr *PersonalizedRecommendations) suggestTerms(userProfile models.UserProfile) models.LoanTerms {
	// Implement logic to suggest loan terms such as duration, interest rate, etc.
	return models.LoanTerms{
		Duration:    12 * time.Month,
		InterestRate: pr.determineInterestRate(userProfile),
	}
}

// determineInterestRate determines the interest rate based on the user's profile.
func (pr *PersonalizedRecommendations) determineInterestRate(userProfile models.UserProfile) float64 {
	// Implement a detailed algorithm to determine interest rate
	return 5.0 // Example fixed interest rate
}

// SendRecommendation sends a personalized loan recommendation to the user.
func (pr *PersonalizedRecommendations) SendRecommendation(recommendation models.LoanRecommendation) error {
	message := fmt.Sprintf("Dear %s, based on your profile, we recommend a loan of %.2f with the following terms: %v",
		recommendation.UserID, recommendation.RecommendedAmount, recommendation.RecommendedTerms)
	return utils.SendNotification(recommendation.UserID, message)
}

// EvaluateApplication evaluates a loan application based on personalized recommendations.
func (pr *PersonalizedRecommendations) EvaluateApplication(application models.LoanApplication) (bool, error) {
	recommendation, err := pr.GenerateRecommendation(application.UserID)
	if err != nil {
		return false, err
	}

	// Implement logic to compare application with recommendation
	if application.Amount <= recommendation.RecommendedAmount &&
		application.Terms.Duration <= recommendation.RecommendedTerms.Duration &&
		application.Terms.InterestRate <= recommendation.RecommendedTerms.InterestRate {
		return true, nil
	}

	return false, nil
}

// MonitorRecommendations monitors the effectiveness of personalized recommendations.
func (pr *PersonalizedRecommendations) MonitorRecommendations() {
	for {
		recommendations := pr.blockchain.GetAllRecommendations()
		for _, recommendation := range recommendations {
			// Implement logic to monitor the effectiveness of recommendations
			// For example, track whether users follow recommendations and repayment success
		}
		time.Sleep(24 * time.Hour) // Adjust the frequency as needed
	}
}

// GetUserRecommendationHistory retrieves the history of recommendations provided to a user.
func (pr *PersonalizedRecommendations) GetUserRecommendationHistory(userID string) ([]models.LoanRecommendation, error) {
	return pr.blockchain.GetUserRecommendations(userID)
}

// UpdateRecommendations updates the recommendations based on new user data.
func (pr *PersonalizedRecommendations) UpdateRecommendations() {
	users := pr.blockchain.GetAllUsers()
	for _, user := range users {
		recommendation, err := pr.GenerateRecommendation(user.UserID)
		if err != nil {
			// Log or handle the error as needed
			continue
		}
		pr.blockchain.UpdateRecommendation(recommendation)
	}
}

// NewScenarioAnalysis creates a new instance of ScenarioAnalysis.
func NewScenarioAnalysis(bc *blockchain.Blockchain, ce crypto.CryptoEngine) *ScenarioAnalysis {
	return &ScenarioAnalysis{
		blockchain:   bc,
		cryptoEngine: ce,
	}
}

// AnalyzeScenario generates a detailed analysis of a loan scenario based on the given parameters.
func (sa *ScenarioAnalysis) AnalyzeScenario(loanID string, amount float64, duration time.Duration, interestRate float64) (models.LoanScenarioAnalysis, error) {
	loan, err := sa.blockchain.GetLoan(loanID)
	if err != nil {
		return models.LoanScenarioAnalysis{}, err
	}

	monthlyPayment := sa.calculateMonthlyPayment(amount, duration, interestRate)
	totalPayment := monthlyPayment * float64(duration.Hours()/24/30)
	totalInterest := totalPayment - amount

	scenario := models.LoanScenarioAnalysis{
		LoanID:        loan.ID,
		Amount:        amount,
		Duration:      duration,
		InterestRate:  interestRate,
		MonthlyPayment: monthlyPayment,
		TotalPayment:  totalPayment,
		TotalInterest: totalInterest,
	}

	return scenario, nil
}

// calculateMonthlyPayment calculates the monthly payment for a loan based on the amount, duration, and interest rate.
func (sa *ScenarioAnalysis) calculateMonthlyPayment(amount float64, duration time.Duration, interestRate float64) float64 {
	monthlyRate := interestRate / 12 / 100
	numberOfPayments := duration.Hours() / 24 / 30
	denominator := 1 - (1 / (1 + monthlyRate) / numberOfPayments)
	return (amount * monthlyRate) / denominator
}

// SimulateRepaymentPlan simulates various repayment plans and their impacts on the borrower's financial situation.
func (sa *ScenarioAnalysis) SimulateRepaymentPlan(userID string, loanID string, scenarios []models.RepaymentScenario) ([]models.RepaymentSimulationResult, error) {
	var results []models.RepaymentSimulationResult

	for _, scenario := range scenarios {
		result, err := sa.simulateSingleRepaymentPlan(userID, loanID, scenario)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// simulateSingleRepaymentPlan simulates a single repayment plan scenario.
func (sa *ScenarioAnalysis) simulateSingleRepaymentPlan(userID string, loanID string, scenario models.RepaymentScenario) (models.RepaymentSimulationResult, error) {
	userProfile, err := sa.blockchain.GetUserProfile(userID)
	if err != nil {
		return models.RepaymentSimulationResult{}, err
	}

	loan, err := sa.blockchain.GetLoan(loanID)
	if err != nil {
		return models.RepaymentSimulationResult{}, err
	}

	monthlyPayment := sa.calculateMonthlyPayment(scenario.Amount, scenario.Duration, scenario.InterestRate)
	totalPayment := monthlyPayment * float64(scenario.Duration.Hours()/24/30)
	totalInterest := totalPayment - scenario.Amount

	remainingIncome := userProfile.AnnualIncome/12 - monthlyPayment

	result := models.RepaymentSimulationResult{
		Scenario:      scenario,
		MonthlyPayment: monthlyPayment,
		TotalPayment:  totalPayment,
		TotalInterest: totalInterest,
		RemainingIncome: remainingIncome,
	}

	return result, nil
}

// GenerateScenarioReport generates a comprehensive report for various loan scenarios.
func (sa *ScenarioAnalysis) GenerateScenarioReport(userID string, loanID string, scenarios []models.RepaymentScenario) (models.ScenarioReport, error) {
	results, err := sa.SimulateRepaymentPlan(userID, loanID, scenarios)
	if err != nil {
		return models.ScenarioReport{}, err
	}

	report := models.ScenarioReport{
		UserID:   userID,
		LoanID:   loanID,
		Scenarios: results,
		GeneratedAt: time.Now(),
	}

	return report, nil
}

// NotifyUser sends the scenario report to the user.
func (sa *ScenarioAnalysis) NotifyUser(report models.ScenarioReport) error {
	userProfile, err := sa.blockchain.GetUserProfile(report.UserID)
	if err != nil {
		return err
	}

	message := fmt.Sprintf("Dear %s, your loan scenario analysis report for Loan ID %s is ready. Please review the details and make informed decisions.",
		userProfile.Name, report.LoanID)
	return utils.SendNotification(userProfile.Email, message)
}

// ExportScenarioReport exports the scenario report in the specified format.
func (sa *ScenarioAnalysis) ExportScenarioReport(report models.ScenarioReport, format string) (string, error) {
	switch format {
	case "CSV":
		return utils.ExportToCSV(report)
	case "JSON":
		return utils.ExportToJSON(report)
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}
