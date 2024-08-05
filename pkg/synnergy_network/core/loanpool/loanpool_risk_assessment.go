package risk_assessment

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/loanpool/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/loanpool/user_management"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/utils"
)


// NewAffordabilityChecks creates a new instance of AffordabilityChecks
func NewAffordabilityChecks(userID string, loanAmount float64, loanTermMonths int) (*AffordabilityChecks, error) {
	user, err := user_management.GetUserDetails(userID)
	if err != nil {
		return nil, err
	}

	return &AffordabilityChecks{
		UserID:            userID,
		LoanAmount:        loanAmount,
		LoanTermMonths:    loanTermMonths,
		UserIncome:        user.Income,
		UserDebts:         user.Debts,
		UserExpenses:      user.Expenses,
		Dependents:        user.Dependents,
		DependentExpenses: user.DependentExpenses,
		AdvisoryLimit:     0.0,
	}, nil
}

// CalculateAffordability checks if the user can afford the loan and calculates the advisory limit
func (a *AffordabilityChecks) CalculateAffordability() (bool, error) {
	monthlyIncome := a.UserIncome / 12
	monthlyDebtPayments := a.UserDebts / 12
	totalExpenses := a.UserExpenses + (a.Dependents * a.DependentExpenses)
	monthlyDisposableIncome := monthlyIncome - (monthlyDebtPayments + totalExpenses)
	monthlyLoanPayment := a.LoanAmount / float64(a.LoanTermMonths)

	a.AdvisoryLimit = monthlyDisposableIncome * 0.4 * float64(a.LoanTermMonths)

	if monthlyLoanPayment > (monthlyDisposableIncome * 0.4) {
		return false, errors.New("loan amount exceeds 40% of monthly disposable income")
	}

	return true, nil
}

// RecordAffordabilityCheck records the result of the affordability check
func (a *AffordabilityChecks) RecordAffordabilityCheck(passed bool) error {
	record := utils.AffordabilityRecord{
		UserID:            a.UserID,
		LoanAmount:        a.LoanAmount,
		LoanTermMonths:    a.LoanTermMonths,
		Passed:            passed,
		Timestamp:         time.Now(),
		AdvisoryLoanLimit: a.AdvisoryLimit,
	}

	return utils.RecordAffordability(record)
}

// PerformSecurityCheck performs a security check for the affordability assessment
func (a *AffordabilityChecks) PerformSecurityCheck() error {
	securityCheck := security.NewSecurityCheck(a.UserID)
	passed, err := securityCheck.PerformCheck()
	if err != nil {
		return err
	}

	if !passed {
		return errors.New("security check failed")
	}

	return nil
}

// CompleteAffordabilityCheck runs all checks and records the result
func (a *AffordabilityChecks) CompleteAffordabilityCheck() (bool, error) {
	if err := a.PerformSecurityCheck(); err != nil {
		return false, err
	}

	affordable, err := a.CalculateAffordability()
	if err != nil {
		return false, err
	}

	if err := a.RecordAffordabilityCheck(affordable); err != nil {
		return false, err
	}

	return affordable, nil
}

// GetAdvisoryLimit returns the advisory loan limit calculated during the affordability check
func (a *AffordabilityChecks) GetAdvisoryLimit() float64 {
	return a.AdvisoryLimit
}

// NewRiskAnalysisAI creates a new instance of RiskAnalysisAI
func NewRiskAnalysisAI(model models.AIModel) *RiskAnalysisAI {
	return &RiskAnalysisAI{
		model: model,
	}
}

// AnalyzeRisk performs an AI-driven risk analysis on the borrower
func (ai *RiskAnalysisAI) AnalyzeRisk(borrower models.Borrower) (models.RiskProfile, error) {
	// Fetching on-chain and off-chain data for analysis
	onChainData := fetchOnChainData(borrower)
	offChainData := fetchOffChainData(borrower)

	// Combining data for AI model input
	data := combineData(onChainData, offChainData)

	// Running the AI model to assess risk
	riskProfile, err := ai.model.Predict(data)
	if err != nil {
		return models.RiskProfile{}, fmt.Errorf("risk analysis failed: %v", err)
	}

	// Returning the generated risk profile
	return riskProfile, nil
}

// fetchOnChainData fetches the on-chain data for the borrower
func fetchOnChainData(borrower models.Borrower) models.OnChainData {
	// Example implementation to fetch on-chain data
	return blockchain.GetOnChainData(borrower.ID)
}

// fetchOffChainData fetches the off-chain data for the borrower
func fetchOffChainData(borrower models.Borrower) models.OffChainData {
	// Example implementation to fetch off-chain data
	return models.OffChainData{
		CreditHistory: fetchCreditHistory(borrower),
		SocialMedia:   fetchSocialMediaData(borrower),
		FinancialDocs: fetchFinancialDocuments(borrower),
	}
}

// combineData combines on-chain and off-chain data for AI model input
func combineData(onChainData models.OnChainData, offChainData models.OffChainData) models.CombinedData {
	// Combine and normalize data
	return models.CombinedData{
		OnChainData:  onChainData,
		OffChainData: offChainData,
	}
}

// fetchCreditHistory fetches the credit history of the borrower
func fetchCreditHistory(borrower models.Borrower) models.CreditHistory {
	// Example implementation to fetch credit history
	return models.GetCreditHistory(borrower.ID)
}

// fetchSocialMediaData fetches the social media data of the borrower
func fetchSocialMediaData(borrower models.Borrower) models.SocialMedia {
	// Example implementation to fetch social media data
	return models.GetSocialMediaData(borrower.ID)
}

// fetchFinancialDocuments fetches financial documents of the borrower
func fetchFinancialDocuments(borrower models.Borrower) models.FinancialDocuments {
	// Example implementation to fetch financial documents
	return models.GetFinancialDocuments(borrower.ID)
}

// RegularReassessment periodically reassesses the risk profile of the borrower
func (ai *RiskAnalysisAI) RegularReassessment(borrower models.Borrower) {
	ticker := time.NewTicker(30 * 24 * time.Hour) // Reassess every 30 days
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			riskProfile, err := ai.AnalyzeRisk(borrower)
			if err != nil {
				fmt.Printf("Reassessment failed for borrower %v: %v\n", borrower.ID, err)
				continue
			}

			// Update risk profile on the blockchain
			err = blockchain.UpdateRiskProfile(borrower.ID, riskProfile)
			if err != nil {
				fmt.Printf("Failed to update risk profile on blockchain for borrower %v: %v\n", borrower.ID, err)
			}
		}
	}
}

// InitiateAIProposalReview performs an AI-driven proposal review
func (ai *RiskAnalysisAI) InitiateAIProposalReview(proposal models.Proposal) (models.ReviewResult, error) {
	// Use AI to evaluate and prioritize the proposal based on urgency and impact
	result, err := ai.model.EvaluateProposal(proposal)
	if err != nil {
		return models.ReviewResult{}, fmt.Errorf("proposal review failed: %v", err)
	}
	return result, nil
}

// NotifyUsers sends notifications to relevant users about the risk analysis results
func (ai *RiskAnalysisAI) NotifyUsers(user models.User, message string) {
	// Example implementation to notify users
	models.SendNotification(user, message)
}

// DetectFraud detects potential fraud in the loan application process using AI
func (ai *RiskAnalysisAI) DetectFraud(application models.LoanApplication) (bool, error) {
	// Example implementation to detect fraud
	fraudDetected, err := ai.model.DetectFraud(application)
	if err != nil {
		return false, fmt.Errorf("fraud detection failed: %v", err)
	}
	return fraudDetected, nil
}

// MonitorPerformance monitors the performance of the AI model
func (ai *RiskAnalysisAI) MonitorPerformance() {
	// Example implementation to monitor AI performance
	performanceMetrics := ai.model.GetPerformanceMetrics()
	fmt.Printf("AI Model Performance: %v\n", performanceMetrics)
}

// AdjustModelParameters dynamically adjusts AI model parameters
func (ai *RiskAnalysisAI) AdjustModelParameters(newParams models.AIModelParams) {
	// Example implementation to adjust AI model parameters
	ai.model.UpdateParameters(newParams)
}

// NewAIDrivenRiskAnalysis initializes a new instance of AIDrivenRiskAnalysis.
func NewAIDrivenRiskAnalysis(userID string, income, debts, expenses float64, dependents int, dependentExpenses float64, loanHistory []LoanHistory, creditScore int) *AIDrivenRiskAnalysis {
	return &AIDrivenRiskAnalysis{
		UserID:              userID,
		UserIncome:          income,
		UserDebts:           debts,
		UserExpenses:        expenses,
		Dependents:          dependents,
		DependentExpenses:   dependentExpenses,
		PreviousLoanHistory: loanHistory,
		CreditScore:         creditScore,
	}
}

// CalculateRiskScore calculates the risk score of the user.
func (a *AIDrivenRiskAnalysis) CalculateRiskScore() {
	// Basic risk score calculation
	debtToIncomeRatio := a.UserDebts / a.UserIncome
	expenseToIncomeRatio := (a.UserExpenses + a.DependentExpenses) / a.UserIncome

	// Factor in credit score, previous loan history, and number of dependents
	historyRisk := 0.0
	for _, history := range a.PreviousLoanHistory {
		if history.Defaulted {
			historyRisk += 1.0
		} else {
			historyRisk -= 0.5
		}
	}

	creditScoreRisk := float64(850 - a.CreditScore) / 850.0
	dependentRisk := float64(a.Dependents) * 0.1

	// Aggregate risk score
	a.RiskScore = 0.5*debtToIncomeRatio + 0.3*expenseToIncomeRatio + 0.1*historyRisk + 0.1*creditScoreRisk + dependentRisk
	if a.RiskScore > 1 {
		a.RiskScore = 1
	} else if a.RiskScore < 0 {
		a.RiskScore = 0
	}
}

// CalculateMaxLoanAmount calculates the maximum loan amount the user can be offered.
func (a *AIDrivenRiskAnalysis) CalculateMaxLoanAmount() {
	a.MaxLoanAmount = a.UserIncome * (1 - a.RiskScore) * 0.2
}

// EvaluateRisk evaluates the risk and advises the maximum loan amount.
func (a *AIDrivenRiskAnalysis) EvaluateRisk() string {
	a.CalculateRiskScore()
	a.CalculateMaxLoanAmount()
	advisory := fmt.Sprintf("User %s has a risk score of %.2f. The maximum loan amount they can be offered is %.2f SYN.", a.UserID, a.RiskScore, a.MaxLoanAmount)
	return advisory
}

// EncryptUserData encrypts the user data using the best encryption method for the situation.
func (a *AIDrivenRiskAnalysis) EncryptUserData() (string, error) {
	// Combining all user data into a single string for encryption
	data := fmt.Sprintf("%s,%f,%f,%f,%d,%f,%d,%f", a.UserID, a.UserIncome, a.UserDebts, a.UserExpenses, a.Dependents, a.DependentExpenses, a.CreditScore, a.RiskScore)
	encryptedData, err := encryption.EncryptData(data)
	if err != nil {
		log.Printf("Error encrypting user data: %v", err)
		return "", err
	}
	return encryptedData, nil
}

// DecryptUserData decrypts the user data.
func (a *AIDrivenRiskAnalysis) DecryptUserData(encryptedData string) error {
	decryptedData, err := encryption.DecryptData(encryptedData)
	if err != nil {
		log.Printf("Error decrypting user data: %v", err)
		return err
	}
	// Parsing decrypted data
	fmt.Sscanf(decryptedData, "%s,%f,%f,%f,%d,%f,%d,%f", &a.UserID, &a.UserIncome, &a.UserDebts, &a.UserExpenses, &a.Dependents, &a.DependentExpenses, &a.CreditScore, &a.RiskScore)
	return nil
}

// DetectFraud uses AI/ML models to detect potential fraud in the application process.
func (a *AIDrivenRiskAnalysis) DetectFraud() bool {
	// Dummy implementation for fraud detection
	// In real-world scenario, this would involve sophisticated AI/ML models
	if a.UserDebts > a.UserIncome*0.8 {
		return true
	}
	return false
}

// NotifyRiskAssessmentResult sends notifications about the risk assessment result.
func (a *AIDrivenRiskAnalysis) NotifyRiskAssessmentResult() {
	notification := fmt.Sprintf("Risk assessment completed for user %s. Risk Score: %.2f, Max Loan Amount: %.2f SYN.", a.UserID, a.RiskScore, a.MaxLoanAmount)
	security.SendNotification(a.UserID, notification)
}

// NewRiskAuditor initializes a new RiskAuditor
func NewRiskAuditor() *RiskAuditor {
	return &RiskAuditor{
		audits: make([]RiskAudit, 0),
	}
}

// ConductAudit performs a risk audit for a given loan
func (ra *RiskAuditor) ConductAudit(loanID string, auditor string, findings string, recommendations string) (RiskAudit, error) {
	auditID := cryptography.GenerateUUID()
	auditDate := time.Now()

	audit := RiskAudit{
		ID:             auditID,
		LoanID:         loanID,
		AuditDate:      auditDate,
		Auditor:        auditor,
		Findings:       findings,
		Recommendations: recommendations,
		Status:         "Pending",
		Verified:       false,
	}

	// Log the audit
	ra.audits = append(ra.audits, audit)

	// Notify relevant parties
	notifications.SendNotification(audit.Auditor, fmt.Sprintf("Audit %s conducted on loan %s", auditID, loanID))

	return audit, nil
}

// VerifyAudit verifies the findings of a risk audit
func (ra *RiskAuditor) VerifyAudit(auditID string, verifier string) error {
	for i, audit := range ra.audits {
		if audit.ID == auditID {
			ra.audits[i].Verified = true
			ra.audits[i].Status = "Verified"

			// Log the verification
			notifications.SendNotification(audit.Auditor, fmt.Sprintf("Audit %s verified by %s", auditID, verifier))
			notifications.SendNotification(verifier, fmt.Sprintf("You have verified audit %s for loan %s", auditID, audit.LoanID))

			return nil
		}
	}
	return fmt.Errorf("audit ID %s not found", auditID)
}

// GetAuditReport generates a comprehensive report for a specific audit
func (ra *RiskAuditor) GetAuditReport(auditID string) (RiskAudit, error) {
	for _, audit := range ra.audits {
		if audit.ID == auditID {
			return audit, nil
		}
	}
	return RiskAudit{}, fmt.Errorf("audit ID %s not found", auditID)
}

// ListAuditsByLoan lists all audits conducted for a specific loan
func (ra *RiskAuditor) ListAuditsByLoan(loanID string) ([]RiskAudit, error) {
	var audits []RiskAudit
	for _, audit := range ra.audits {
		if audit.LoanID == loanID {
			audits = append(audits, audit)
		}
	}
	if len(audits) == 0 {
		return nil, fmt.Errorf("no audits found for loan ID %s", loanID)
	}
	return audits, nil
}

// ArchiveAudit archives a completed audit to the blockchain
func (ra *RiskAuditor) ArchiveAudit(auditID string) error {
	for i, audit := range ra.audits {
		if audit.ID == auditID {
			// Ensure the audit is verified before archiving
			if !audit.Verified {
				return fmt.Errorf("audit %s is not verified and cannot be archived", auditID)
			}

			// Archive the audit to the blockchain
			auditData := fmt.Sprintf("AuditID: %s, LoanID: %s, Date: %s, Auditor: %s, Findings: %s, Recommendations: %s, Status: %s",
				audit.ID, audit.LoanID, audit.AuditDate, audit.Auditor, audit.Findings, audit.Recommendations, audit.Status)
			blockchain.RecordTransaction(auditData)

			// Notify relevant parties
			notifications.SendNotification(audit.Auditor, fmt.Sprintf("Audit %s archived to the blockchain", auditID))

			// Remove from active audits list
			ra.audits = append(ra.audits[:i], ra.audits[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("audit ID %s not found", auditID)
}

// NewRiskEvaluation creates a new instance of RiskEvaluation.
func NewRiskEvaluation(loanAmount, interestRate float64, loanTerm int, borrowerIncome, borrowerDebts, borrowerExpenses float64, dependents int, dependentExpenses float64, creditScore int, collateralValue float64, collateralType string) *RiskEvaluation {
	return &RiskEvaluation{
		loanAmount:       loanAmount,
		interestRate:     interestRate,
		loanTerm:         loanTerm,
		borrowerIncome:   borrowerIncome,
		borrowerDebts:    borrowerDebts,
		borrowerExpenses: borrowerExpenses,
		dependents:       dependents,
		dependentExpenses: dependentExpenses,
		creditScore:      creditScore,
		collateralValue:  collateralValue,
		collateralType:   collateralType,
		createdAt:        time.Now(),
		updatedAt:        time.Now(),
	}
}

// CalculateDebtToIncomeRatio calculates the debt-to-income ratio for the borrower.
func (re *RiskEvaluation) CalculateDebtToIncomeRatio() float64 {
	totalDebt := re.borrowerDebts + re.loanAmount
	return totalDebt / re.borrowerIncome
}

// CalculateExpenseToIncomeRatio calculates the expense-to-income ratio for the borrower.
func (re *RiskEvaluation) CalculateExpenseToIncomeRatio() float64 {
	totalExpenses := re.borrowerExpenses + (re.dependents * re.dependentExpenses)
	return totalExpenses / re.borrowerIncome
}

// CalculateLoanToValueRatio calculates the loan-to-value ratio for the collateral.
func (re *RiskEvaluation) CalculateLoanToValueRatio() float64 {
	return re.loanAmount / re.collateralValue
}

// EvaluateRiskScore evaluates the overall risk score based on various factors.
func (re *RiskEvaluation) EvaluateRiskScore() int {
	dtiRatio := re.CalculateDebtToIncomeRatio()
	etiRatio := re.CalculateExpenseToIncomeRatio()
	ltvRatio := re.CalculateLoanToValueRatio()

	// Risk scoring logic
	score := 100
	score -= int(dtiRatio * 50)
	score -= int(etiRatio * 30)
	score -= int(ltvRatio * 20)

	// Adjust based on credit score
	if re.creditScore < 600 {
		score -= 20
	} else if re.creditScore < 700 {
		score -= 10
	}

	// Ensure score is within 0-100 range
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return score
}

// GetLoanOffer provides a loan offer based on the evaluated risk score.
func (re *RiskEvaluation) GetLoanOffer() (string, error) {
	riskScore := re.EvaluateRiskScore()
	if riskScore >= 80 {
		return fmt.Sprintf("Loan Approved: Amount - $%.2f, Interest Rate - %.2f%%", re.loanAmount, re.interestRate), nil
	} else if riskScore >= 50 {
		return "Loan Approved with Higher Interest Rate or Reduced Amount", nil
	}
	return "Loan Denied: High Risk", nil
}

// EncryptSensitiveData encrypts sensitive data within the risk evaluation.
func (re *RiskEvaluation) EncryptSensitiveData() error {
	encryptedIncome, err := encryption.Encrypt(fmt.Sprintf("%f", re.borrowerIncome))
	if err != nil {
		return err
	}
	encryptedDebts, err := encryption.Encrypt(fmt.Sprintf("%f", re.borrowerDebts))
	if err != nil {
		return err
	}
	encryptedExpenses, err := encryption.Encrypt(fmt.Sprintf("%f", re.borrowerExpenses))
	if err != nil {
		return err
	}
	encryptedCollateral, err := encryption.Encrypt(fmt.Sprintf("%f", re.collateralValue))
	if err != nil {
		return err
	}

	re.borrowerIncome = encryptedIncome
	re.borrowerDebts = encryptedDebts
	re.borrowerExpenses = encryptedExpenses
	re.collateralValue = encryptedCollateral

	return nil
}

// DecryptSensitiveData decrypts sensitive data within the risk evaluation.
func (re *RiskEvaluation) DecryptSensitiveData() error {
	decryptedIncome, err := encryption.Decrypt(fmt.Sprintf("%f", re.borrowerIncome))
	if err != nil {
		return err
	}
	decryptedDebts, err := encryption.Decrypt(fmt.Sprintf("%f", re.borrowerDebts))
	if err != nil {
		return err
	}
	decryptedExpenses, err := encryption.Decrypt(fmt.Sprintf("%f", re.borrowerExpenses))
	if err != nil {
		return err
	}
	decryptedCollateral, err := encryption.Decrypt(fmt.Sprintf("%f", re.collateralValue))
	if err != nil {
		return err
	}

	re.borrowerIncome = decryptedIncome
	re.borrowerDebts = decryptedDebts
	re.borrowerExpenses = decryptedExpenses
	re.collateralValue = decryptedCollateral

	return nil
}

// UpdateRiskEvaluation updates the risk evaluation details.
func (re *RiskEvaluation) UpdateRiskEvaluation(loanAmount, interestRate float64, loanTerm int, borrowerIncome, borrowerDebts, borrowerExpenses float64, dependents int, dependentExpenses float64, creditScore int, collateralValue float64, collateralType string) {
	re.loanAmount = loanAmount
	re.interestRate = interestRate
	re.loanTerm = loanTerm
	re.borrowerIncome = borrowerIncome
	re.borrowerDebts = borrowerDebts
	re.borrowerExpenses = borrowerExpenses
	re.dependents = dependents
	re.dependentExpenses = dependentExpenses
	re.creditScore = creditScore
	re.collateralValue = collateralValue
	re.collateralType = collateralType
	re.updatedAt = time.Now()
}

// DisplayRiskEvaluation displays the risk evaluation details.
func (re *RiskEvaluation) DisplayRiskEvaluation() {
	fmt.Printf("Loan Amount: $%.2f\n", re.loanAmount)
	fmt.Printf("Interest Rate: %.2f%%\n", re.interestRate)
	fmt.Printf("Loan Term: %d months\n", re.loanTerm)
	fmt.Printf("Borrower Income: $%.2f\n", re.borrowerIncome)
	fmt.Printf("Borrower Debts: $%.2f\n", re.borrowerDebts)
	fmt.Printf("Borrower Expenses: $%.2f\n", re.borrowerExpenses)
	fmt.Printf("Dependents: %d\n", re.dependents)
	fmt.Printf("Dependent Expenses: $%.2f\n", re.dependentExpenses)
	fmt.Printf("Credit Score: %d\n", re.creditScore)
	fmt.Printf("Collateral Value: $%.2f\n", re.collateralValue)
	fmt.Printf("Collateral Type: %s\n", re.collateralType)
	fmt.Printf("Debt-to-Income Ratio: %.2f\n", re.CalculateDebtToIncomeRatio())
	fmt.Printf("Expense-to-Income Ratio: %.2f\n", re.CalculateExpenseToIncomeRatio())
	fmt.Printf("Loan-to-Value Ratio: %.2f\n", re.CalculateLoanToValueRatio())
	fmt.Printf("Risk Score: %d\n", re.EvaluateRiskScore())
}


// NewAIDrivenRiskAnalysis creates a new instance of AIDrivenRiskAnalysis.
func NewAIDrivenRiskAnalysis(model common.AIModel) *AIDrivenRiskAnalysis {
	return &AIDrivenRiskAnalysis{
		aiModel: model,
	}
}

// AnalyzeRisk analyzes the risk of a loan application.
func (a *AIDrivenRiskAnalysis) AnalyzeRisk(application models.LoanApplication) (models.RiskProfile, error) {
	// Validate application data
	err := validation.ValidateLoanApplication(application)
	if err != nil {
		return models.RiskProfile{}, err
	}

	// Perform AI-driven risk analysis
	riskScore, err := a.aiModel.Predict(application)
	if err != nil {
		return models.RiskProfile{}, err
	}

	// Compute risk level based on the risk score
	riskLevel := a.computeRiskLevel(riskScore)
	riskProfile := models.RiskProfile{
		ApplicationID: application.ID,
		RiskScore:     riskScore,
		RiskLevel:     riskLevel,
	}

	return riskProfile, nil
}

// computeRiskLevel computes the risk level based on the risk score.
func (a *AIDrivenRiskAnalysis) computeRiskLevel(riskScore float64) models.RiskLevel {
	switch {
	case riskScore < 0.2:
		return models.LowRisk
	case riskScore < 0.5:
		return models.MediumRisk
	case riskScore < 0.8:
		return models.HighRisk
	default:
		return models.VeryHighRisk
	}
}

// PerformScoring performs comprehensive scoring including AI-driven analysis and financial ratios.
func (a *AIDrivenRiskAnalysis) PerformScoring(application models.LoanApplication) (models.ScoringResult, error) {
	// Basic validation
	if err := validation.ValidateLoanApplication(application); err != nil {
		return models.ScoringResult{}, err
	}

	// AI-driven risk analysis
	riskProfile, err := a.AnalyzeRisk(application)
	if err != nil {
		return models.ScoringResult{}, err
	}

	// Financial ratios analysis
	debtToIncomeRatio := a.calculateDebtToIncomeRatio(application)
	expenseRatio := a.calculateExpenseRatio(application)

	// Aggregate scoring result
	scoringResult := models.ScoringResult{
		RiskProfile:      riskProfile,
		DebtToIncome:     debtToIncomeRatio,
		ExpenseRatio:     expenseRatio,
		Advisory:         a.generateAdvisory(riskProfile, debtToIncomeRatio, expenseRatio),
	}

	return scoringResult, nil
}

// calculateDebtToIncomeRatio calculates the debt to income ratio.
func (a *AIDrivenRiskAnalysis) calculateDebtToIncomeRatio(application models.LoanApplication) float64 {
	if application.Income <= 0 {
		return math.Inf(1)
	}
	return application.Debts / application.Income
}

// calculateExpenseRatio calculates the expense ratio.
func (a *AIDrivenRiskAnalysis) calculateExpenseRatio(application models.LoanApplication) float64 {
	if application.Income <= 0 {
		return math.Inf(1)
	}
	return application.Expenses / application.Income
}

// generateAdvisory generates advisory based on risk profile and financial ratios.
func (a *AIDrivenRiskAnalysis) generateAdvisory(riskProfile models.RiskProfile, debtToIncome, expenseRatio float64) string {
	advisory := "Advisory based on the analysis:\n"

	switch riskProfile.RiskLevel {
	case models.LowRisk:
		advisory += "- The applicant is low risk.\n"
	case models.MediumRisk:
		advisory += "- The applicant is medium risk.\n"
	case models.HighRisk:
		advisory += "- The applicant is high risk.\n"
	case models.VeryHighRisk:
		advisory += "- The applicant is very high risk.\n"
	}

	advisory += a.financialAdvisory(debtToIncome, expenseRatio)

	return advisory
}

// financialAdvisory generates financial advisory based on debt to income and expense ratio.
func (a *AIDrivenRiskAnalysis) financialAdvisory(debtToIncome, expenseRatio float64) string {
	advisory := ""

	if debtToIncome > 0.4 {
		advisory += "- The debt to income ratio is high. Consider reducing debt.\n"
	} else {
		advisory += "- The debt to income ratio is acceptable.\n"
	}

	if expenseRatio > 0.6 {
		advisory += "- The expense ratio is high. Consider reducing expenses.\n"
	} else {
		advisory += "- The expense ratio is acceptable.\n"
	}

	return advisory
}

// EvaluateApplication evaluates the loan application using AI and provides a detailed report.
func (a *AIDrivenRiskAnalysis) EvaluateApplication(application models.LoanApplication) (models.EvaluationReport, error) {
	scoringResult, err := a.PerformScoring(application)
	if err != nil {
		return models.EvaluationReport{}, err
	}

	evaluationReport := models.EvaluationReport{
		ApplicationID: application.ID,
		ScoringResult: scoringResult,
		Timestamp:     time.Now(),
	}

	return evaluationReport, nil
}

// NewRiskReportingService creates a new instance of RiskReportingService.
func NewRiskReportingService(storage storage.Storage, notificationSvc notifications.NotificationService, encryptionKey string) *RiskReportingService {
	return &RiskReportingService{
		Storage:         storage,
		NotificationSvc: notificationSvc,
		EncryptionKey:   encryptionKey,
	}
}

// GenerateRiskReport generates a risk report for a specific loan.
func (service *RiskReportingService) GenerateRiskReport(borrowerID, loanID string, riskScore float64, details string) (*RiskReport, error) {
	encryptedDetails, err := encryption.Encrypt(details, service.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt report details: %v", err)
	}

	report := &RiskReport{
		ID:            generateReportID(),
		BorrowerID:    borrowerID,
		LoanID:        loanID,
		ReportDetails: encryptedDetails,
		RiskScore:     riskScore,
		GeneratedAt:   time.Now(),
	}

	err = service.Storage.Save(report.ID, report)
	if err != nil {
		return nil, fmt.Errorf("failed to save risk report: %v", err)
	}

	err = service.NotificationSvc.Notify(borrowerID, "Your risk report has been generated.")
	if err != nil {
		return nil, fmt.Errorf("failed to send notification: %v", err)
	}

	return report, nil
}

// GetRiskReport retrieves a risk report by ID.
func (service *RiskReportingService) GetRiskReport(reportID string) (*RiskReport, error) {
	data, err := service.Storage.Get(reportID)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk report: %v", err)
	}

	report := &RiskReport{}
	err = data.Decode(report)
	if err != nil {
		return nil, fmt.Errorf("failed to decode risk report: %v", err)
	}

	decryptedDetails, err := encryption.Decrypt(report.ReportDetails, service.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt report details: %v", err)
	}
	report.ReportDetails = decryptedDetails

	return report, nil
}

// ListRiskReports lists all risk reports for a specific borrower.
func (service *RiskReportingService) ListRiskReports(borrowerID string) ([]*RiskReport, error) {
	data, err := service.Storage.List("borrower_id", borrowerID)
	if err != nil {
		return nil, fmt.Errorf("failed to list risk reports: %v", err)
	}

	var reports []*RiskReport
	for _, item := range data {
		report := &RiskReport{}
		err := item.Decode(report)
		if err != nil {
			return nil, fmt.Errorf("failed to decode risk report: %v", err)
		}

		decryptedDetails, err := encryption.Decrypt(report.ReportDetails, service.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt report details: %v", err)
		}
		report.ReportDetails = decryptedDetails

		reports = append(reports, report)
	}

	return reports, nil
}

// generateReportID generates a unique ID for each risk report.
func generateReportID() string {
	return fmt.Sprintf("report_%d", time.Now().UnixNano())
}


