package loan_services

import (
	"errors"
	"sync"
	"time"
)

const (
	LoanStatusSubmitted   common.LoanStatus = "Submitted"
	LoanStatusApproved    LoanStatus = "Approved"
	LoanStatusDisbursed   LoanStatus = "Disbursed"
	LoanStatusRepaid      LoanStatus = "Repaid"
	LoanStatusDefaulted   LoanStatus = "Defaulted"
)

// NewAutomatedLoanManagement initializes a new AutomatedLoanManagement instance.
func NewAutomatedLoanManagement() *AutomatedLoanManagement {
	return &AutomatedLoanManagement{
		loans:      make(map[string]*Loan),
		repayments: make(map[string][]Repayment),
	}
}

// SubmitLoanProposal allows a user to submit a loan proposal.
func (alm *AutomatedLoanManagement) SubmitLoanProposal(borrowerID string, amount, interestRate float64, term int, collateral string) (string, error) {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	loanID := generateID()
	loan := &Loan{
		ID:           loanID,
		BorrowerID:   borrowerID,
		Amount:       amount,
		InterestRate: interestRate,
		Term:         term,
		Status:       LoanStatusSubmitted,
		Collateral:   collateral,
	}

	alm.loans[loanID] = loan
	return loanID, nil
}

// ApproveLoanProposal approves a submitted loan proposal.
func (alm *AutomatedLoanManagement) ApproveLoanProposal(loanID string) error {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	loan, exists := alm.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	if loan.Status != LoanStatusSubmitted {
		return errors.New("loan cannot be approved in its current status")
	}

	now := time.Now()
	loan.Status = LoanStatusApproved
	loan.ApprovalDate = &now
	return nil
}

// DisburseLoan disburses the approved loan to the borrower.
func (alm *AutomatedLoanManagement) DisburseLoan(loanID string) error {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	loan, exists := alm.loans[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	if loan.Status != LoanStatusApproved {
		return errors.New("loan cannot be disbursed in its current status")
	}

	now := time.Now()
	loan.Status = LoanStatusDisbursed
	loan.DisbursementDate = &now
	loan.RepaymentSchedule = generateRepaymentSchedule(loan.Amount, loan.InterestRate, loan.Term)
	return nil
}

// RepayLoan processes a loan repayment.
func (alm *AutomatedLoanManagement) RepayLoan(loanID string, amount float64) (string, error) {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	loan, exists := alm.loans[loanID]
	if !exists {
		return "", errors.New("loan not found")
	}

	if loan.Status != LoanStatusDisbursed {
		return "", errors.New("loan is not in a repayable status")
	}

	repaymentID := generateID()
	repayment := Repayment{
		ID:     repaymentID,
		LoanID: loanID,
		Amount: amount,
		Date:   time.Now(),
	}

	alm.repayments[loanID] = append(alm.repayments[loanID], repayment)
	updateLoanStatus(loan, alm.repayments[loanID])

	return repaymentID, nil
}

// GetLoan retrieves loan details by loan ID.
func (alm *AutomatedLoanManagement) GetLoan(loanID string) (*Loan, error) {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	loan, exists := alm.loans[loanID]
	if !exists {
		return nil, errors.New("loan not found")
	}

	return loan, nil
}

// GetRepaymentSchedule retrieves the repayment schedule for a loan.
func (alm *AutomatedLoanManagement) GetRepaymentSchedule(loanID string) ([]Repayment, error) {
	alm.mu.Lock()
	defer alm.mu.Unlock()

	repayments, exists := alm.repayments[loanID]
	if !exists {
		return nil, errors.New("repayment schedule not found")
	}

	return repayments, nil
}

// generateRepaymentSchedule generates a repayment schedule based on loan amount, interest rate, and term.
func generateRepaymentSchedule(amount, interestRate float64, term int) []Repayment {
	// Implementation of repayment schedule generation (e.g., amortization)
	// This is a placeholder implementation
	return []Repayment{}
}

// updateLoanStatus updates the loan status based on the repayment history.
func updateLoanStatus(loan *Loan, repayments []Repayment) {
	// Implementation of loan status update logic based on repayments
}

// generateID generates a unique ID for loans and repayments.
func generateID() string {
	// Implementation of unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}

// NewLoanCalculationService initializes a new LoanCalculationService instance.
func NewLoanCalculationService() *LoanCalculationService {
	return &LoanCalculationService{}
}

// CalculateEMI calculates the Equated Monthly Installment (EMI) for a loan.
func (lcs *LoanCalculationService) CalculateEMI(principal float64, annualInterestRate float64, termInMonths int) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	if principal <= 0 || annualInterestRate <= 0 || termInMonths <= 0 {
		return 0, errors.New("invalid input parameters")
	}

	monthlyInterestRate := annualInterestRate / 12 / 100
	emi := (principal * monthlyInterestRate * math.Pow(1+monthlyInterestRate, float64(termInMonths))) / (math.Pow(1+monthlyInterestRate, float64(termInMonths)) - 1)

	return emi, nil
}

// CalculateTotalPayment calculates the total payment over the life of the loan.
func (lcs *LoanCalculationService) CalculateTotalPayment(principal float64, annualInterestRate float64, termInMonths int) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	emi, err := lcs.CalculateEMI(principal, annualInterestRate, termInMonths)
	if err != nil {
		return 0, err
	}

	totalPayment := emi * float64(termInMonths)
	return totalPayment, nil
}

// CalculateInterestComponent calculates the interest component of a specific EMI.
func (lcs *LoanCalculationService) CalculateInterestComponent(principal float64, annualInterestRate float64, termInMonths int, installmentNumber int) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	if principal <= 0 || annualInterestRate <= 0 || termInMonths <= 0 || installmentNumber <= 0 || installmentNumber > termInMonths {
		return 0, errors.New("invalid input parameters")
	}

	monthlyInterestRate := annualInterestRate / 12 / 100
	emi, err := lcs.CalculateEMI(principal, annualInterestRate, termInMonths)
	if err != nil {
		return 0, err
	}

	outstandingPrincipal := principal * math.Pow(1+monthlyInterestRate, float64(termInMonths)) - emi*math.Pow(1+monthlyInterestRate, float64(termInMonths-installmentNumber))

	interestComponent := outstandingPrincipal * monthlyInterestRate
	return interestComponent, nil
}

// CalculatePrincipalComponent calculates the principal component of a specific EMI.
func (lcs *LoanCalculationService) CalculatePrincipalComponent(principal float64, annualInterestRate float64, termInMonths int, installmentNumber int) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	interestComponent, err := lcs.CalculateInterestComponent(principal, annualInterestRate, termInMonths, installmentNumber)
	if err != nil {
		return 0, err
	}

	emi, err := lcs.CalculateEMI(principal, annualInterestRate, termInMonths)
	if err != nil {
		return 0, err
	}

	principalComponent := emi - interestComponent
	return principalComponent, nil
}

// CalculateAmortizationSchedule generates the amortization schedule for the loan.
func (lcs *LoanCalculationService) CalculateAmortizationSchedule(principal float64, annualInterestRate float64, termInMonths int) ([]AmortizationInstallment, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	var schedule []AmortizationInstallment

	for i := 1; i <= termInMonths; i++ {
		interestComponent, err := lcs.CalculateInterestComponent(principal, annualInterestRate, termInMonths, i)
		if err != nil {
			return nil, err
		}

		principalComponent, err := lcs.CalculatePrincipalComponent(principal, annualInterestRate, termInMonths, i)
		if err != nil {
			return nil, err
		}

		installment := AmortizationInstallment{
			InstallmentNumber: i,
			PrincipalComponent: principalComponent,
			InterestComponent:  interestComponent,
			RemainingBalance:   principal - (principalComponent * float64(i)),
		}

		schedule = append(schedule, installment)
	}

	return schedule, nil
}

// AmortizationInstallment represents an installment in the amortization schedule.
type AmortizationInstallment struct {
	InstallmentNumber  int
	PrincipalComponent float64
	InterestComponent  float64
	RemainingBalance   float64
}

// CalculateRemainingBalance calculates the remaining balance of the loan after a specific installment.
func (lcs *LoanCalculationService) CalculateRemainingBalance(principal float64, annualInterestRate float64, termInMonths int, paidInstallments int) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	if principal <= 0 || annualInterestRate <= 0 || termInMonths <= 0 || paidInstallments < 0 || paidInstallments > termInMonths {
		return 0, errors.New("invalid input parameters")
	}

	emi, err := lcs.CalculateEMI(principal, annualInterestRate, termInMonths)
	if err != nil {
		return 0, err
	}

	remainingBalance := principal * math.Pow(1+annualInterestRate/12/100, float64(termInMonths)) - emi*math.Pow(1+annualInterestRate/12/100, float64(termInMonths-paidInstallments))

	return remainingBalance, nil
}

// CalculateEarlyRepaymentPenalty calculates the penalty for early repayment of the loan.
func (lcs *LoanCalculationService) CalculateEarlyRepaymentPenalty(principal float64, annualInterestRate float64, termInMonths int, paidInstallments int, penaltyRate float64) (float64, error) {
	lcs.mu.Lock()
	defer lcs.mu.Unlock()

	remainingBalance, err := lcs.CalculateRemainingBalance(principal, annualInterestRate, termInMonths, paidInstallments)
	if err != nil {
		return 0, err
	}

	penalty := remainingBalance * penaltyRate / 100
	return penalty, nil
}

// GenerateID generates a unique ID for loans and repayments.
func generateID() string {
	// Implement unique ID generation logic (e.g., UUID)
	return "unique-id-placeholder"
}

const (
	NotificationTypeProposalUpdate common.NotificationType = "ProposalUpdate"
	NotificationTypeLoanApproval   NotificationType = "LoanApproval"
	NotificationTypeRepayment      NotificationType = "Repayment"
	NotificationTypeSecurity       NotificationType = "Security"
)

// NewNotificationService initializes a new NotificationService instance.
func NewNotificationService() *NotificationService {
	return &NotificationService{
		notifications:   make(map[string][]Notification),
		userPreferences: make(map[string]UserPreferences),
	}
}

// AddUserPreferences adds or updates notification preferences for a user.
func (ns *NotificationService) AddUserPreferences(prefs UserPreferences) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.userPreferences[prefs.UserID] = prefs
}

// SendNotification sends a notification to the user based on their preferences.
func (ns *NotificationService) SendNotification(userID string, notifType NotificationType, message string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	prefs, exists := ns.userPreferences[userID]
	if !exists {
		return nil // No preferences set for the user, skip sending notification
	}

	if !prefs.NotificationTypes[notifType] {
		return nil // User has opted out of this type of notification
	}

	notification := Notification{
		ID:        generateID(),
		UserID:    userID,
		Type:      notifType,
		Message:   message,
		Timestamp: time.Now(),
		IsRead:    false,
		Channel:   prefs.PreferredChannel,
	}

	ns.notifications[userID] = append(ns.notifications[userID], notification)
	ns.sendToChannel(notification)
	return nil
}

// GetNotifications retrieves all notifications for a user.
func (ns *NotificationService) GetNotifications(userID string) ([]Notification, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	notifications, exists := ns.notifications[userID]
	if !exists {
		return nil, nil
	}

	return notifications, nil
}

// MarkAsRead marks a notification as read.
func (ns *NotificationService) MarkAsRead(userID, notificationID string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	notifications, exists := ns.notifications[userID]
	if !exists {
		return nil
	}

	for i, notif := range notifications {
		if notif.ID == notificationID {
			ns.notifications[userID][i].IsRead = true
			return nil
		}
	}

	return nil
}

// sendToChannel sends the notification to the specified channel.
func (ns *NotificationService) sendToChannel(notification Notification) {
	switch notification.Channel {
	case "email":
		ns.sendEmail(notification)
	case "SMS":
		ns.sendSMS(notification)
	case "in-app":
		ns.sendInApp(notification)
	}
}

// sendEmail sends an email notification.
func (ns *NotificationService) sendEmail(notification Notification) {
	// Implementation for sending email notification
}

// sendSMS sends an SMS notification.
func (ns *NotificationService) sendSMS(notification Notification) {
	// Implementation for sending SMS notification
}

// sendInApp sends an in-app notification.
func (ns *NotificationService) sendInApp(notification Notification) {
	// Implementation for sending in-app notification
}

// generateID generates a unique ID for notifications.
func generateID() string {
	// Implementation of unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}

// NewLoanServiceAudits initializes a new LoanServiceAudits instance.
func NewLoanServiceAudits() *LoanServiceAudits {
	return &LoanServiceAudits{
		auditRecords: []AuditRecord{},
		auditors:     make(map[string]Auditor),
	}
}

// AddAuditor adds a new auditor to the system.
func (lsa *LoanServiceAudits) AddAuditor(id, name, role string) error {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	if _, exists := lsa.auditors[id]; exists {
		return fmt.Errorf("auditor with ID %s already exists", id)
	}

	lsa.auditors[id] = Auditor{
		ID:   id,
		Name: name,
		Role: role,
	}
	return nil
}

// RemoveAuditor removes an auditor from the system.
func (lsa *LoanServiceAudits) RemoveAuditor(id string) error {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	if _, exists := lsa.auditors[id]; !exists {
		return fmt.Errorf("auditor with ID %s does not exist", id)
	}

	delete(lsa.auditors, id)
	return nil
}

// RecordAudit logs an audit event.
func (lsa *LoanServiceAudits) RecordAudit(action, performedBy, details string) error {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	if _, exists := lsa.auditors[performedBy]; !exists {
		return fmt.Errorf("auditor with ID %s does not exist", performedBy)
	}

	auditRecord := AuditRecord{
		ID:          generateID(),
		Timestamp:   time.Now(),
		Action:      action,
		PerformedBy: performedBy,
		Details:     details,
	}

	lsa.auditRecords = append(lsa.auditRecords, auditRecord)
	return nil
}

// GetAuditRecords retrieves all audit records.
func (lsa *LoanServiceAudits) GetAuditRecords() []AuditRecord {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	return lsa.auditRecords
}

// GetAuditRecordsByAuditor retrieves audit records for a specific auditor.
func (lsa *LoanServiceAudits) GetAuditRecordsByAuditor(auditorID string) ([]AuditRecord, error) {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	if _, exists := lsa.auditors[auditorID]; !exists {
		return nil, fmt.Errorf("auditor with ID %s does not exist", auditorID)
	}

	var records []AuditRecord
	for _, record := range lsa.auditRecords {
		if record.PerformedBy == auditorID {
			records = append(records, record)
		}
	}

	return records, nil
}

// GetAuditors retrieves all auditors.
func (lsa *LoanServiceAudits) GetAuditors() map[string]Auditor {
	lsa.mu.Lock()
	defer lsa.mu.Unlock()

	return lsa.auditors
}

// Generate a unique ID for audit records and auditors.
func generateID() string {
	// Implement unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}

// NewLoanServiceMonitoring initializes a new LoanServiceMonitoring instance.
func NewLoanServiceMonitoring() *LoanServiceMonitoring {
	return &LoanServiceMonitoring{
		loanPerformance: make(map[string]LoanPerformance),
		anomalies:       make(map[string]Anomaly),
		alerts:          make(map[string][]Alert),
	}
}

// TrackLoanPerformance tracks the performance of a loan.
func (lsm *LoanServiceMonitoring) TrackLoanPerformance(loanID, borrowerID string, totalRepayments, expectedRepayments float64, nextRepaymentDate time.Time) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	lsm.loanPerformance[loanID] = LoanPerformance{
		LoanID:             loanID,
		BorrowerID:         borrowerID,
		TotalRepayments:    totalRepayments,
		ExpectedRepayments: expectedRepayments,
		NextRepaymentDate:  nextRepaymentDate,
		PerformanceIndicator: (totalRepayments / expectedRepayments) * 100,
	}
}

// UpdateRepayment updates the repayment information for a loan.
func (lsm *LoanServiceMonitoring) UpdateRepayment(loanID string, repaymentAmount float64, repaymentDate time.Time) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	loanPerf, exists := lsm.loanPerformance[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	loanPerf.TotalRepayments += repaymentAmount
	loanPerf.LastRepaymentDate = repaymentDate
	loanPerf.PerformanceIndicator = (loanPerf.TotalRepayments / loanPerf.ExpectedRepayments) * 100

	lsm.loanPerformance[loanID] = loanPerf
	return nil
}

// DetectAnomalies detects anomalies in loan performance.
func (lsm *LoanServiceMonitoring) DetectAnomalies(loanID string) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	loanPerf, exists := lsm.loanPerformance[loanID]
	if !exists {
		return errors.New("loan not found")
	}

	if loanPerf.PerformanceIndicator < 80.0 {
		anomaly := Anomaly{
			ID:          generateID(),
			LoanID:      loanID,
			Description: fmt.Sprintf("Low performance indicator: %.2f", loanPerf.PerformanceIndicator),
			DetectedAt:  time.Now(),
			Resolved:    false,
		}
		lsm.anomalies[anomaly.ID] = anomaly
		lsm.SendAlert(loanPerf.BorrowerID, anomaly.Description)
	}

	return nil
}

// ResolveAnomaly marks an anomaly as resolved.
func (lsm *LoanServiceMonitoring) ResolveAnomaly(anomalyID string) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	anomaly, exists := lsm.anomalies[anomalyID]
	if !exists {
		return errors.New("anomaly not found")
	}

	anomaly.Resolved = true
	lsm.anomalies[anomalyID] = anomaly
	return nil
}

// SendAlert sends an alert to the user.
func (lsm *LoanServiceMonitoring) SendAlert(userID, message string) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	alert := Alert{
		ID:        generateID(),
		UserID:    userID,
		Message:   message,
		Timestamp: time.Now(),
		Read:      false,
	}

	lsm.alerts[userID] = append(lsm.alerts[userID], alert)
}

// GetAlerts retrieves all alerts for a user.
func (lsm *LoanServiceMonitoring) GetAlerts(userID string) ([]Alert, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	alerts, exists := lsm.alerts[userID]
	if !exists {
		return nil, errors.New("no alerts found for user")
	}

	return alerts, nil
}

// MarkAlertAsRead marks an alert as read.
func (lsm *LoanServiceMonitoring) MarkAlertAsRead(userID, alertID string) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	alerts, exists := lsm.alerts[userID]
	if !exists {
		return errors.New("no alerts found for user")
	}

	for i, alert := range alerts {
		if alert.ID == alertID {
			lsm.alerts[userID][i].Read = true
			return nil
		}
	}

	return errors.New("alert not found")
}

// generateID generates a unique ID for records.
func generateID() string {
	// Implement a proper unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}

// NewLoanServiceReporting initializes a new LoanServiceReporting instance.
func NewLoanServiceReporting() *LoanServiceReporting {
	return &LoanServiceReporting{
		reportData: []ReportData{},
	}
}

// GenerateReport generates a new report based on the provided parameters.
func (lsr *LoanServiceReporting) GenerateReport(reportType, generatedBy, details string) (string, error) {
	lsr.mu.Lock()
	defer lsr.mu.Unlock()

	reportID := generateID()
	timestamp := time.Now()
	filePath := "/path/to/reports/" + reportID + ".csv"

	reportData := ReportData{
		ID:          reportID,
		Timestamp:   timestamp,
		ReportType:  reportType,
		GeneratedBy: generatedBy,
		Details:     details,
		FilePath:    filePath,
	}

	lsr.reportData = append(lsr.reportData, reportData)

	// Generate CSV report
	err := lsr.createCSVReport(filePath, reportData)
	if err != nil {
		return "", err
	}

	return reportID, nil
}

// createCSVReport creates a CSV file for the report data.
func (lsr *LoanServiceReporting) createCSVReport(filePath string, reportData ReportData) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Writing CSV headers
	err = writer.Write([]string{"ID", "Timestamp", "ReportType", "GeneratedBy", "Details"})
	if err != nil {
		return err
	}

	// Writing report data
	err = writer.Write([]string{
		reportData.ID,
		reportData.Timestamp.String(),
		reportData.ReportType,
		reportData.GeneratedBy,
		reportData.Details,
	})
	if err != nil {
		return err
	}

	return nil
}

// GetReport retrieves the details of a report based on the report ID.
func (lsr *LoanServiceReporting) GetReport(reportID string) (ReportData, error) {
	lsr.mu.Lock()
	defer lsr.mu.Unlock()

	for _, report := range lsr.reportData {
		if report.ID == reportID {
			return report, nil
		}
	}

	return ReportData{}, errors.New("report not found")
}

// ListReports retrieves a list of all reports generated.
func (lsr *LoanServiceReporting) ListReports() []ReportData {
	lsr.mu.Lock()
	defer lsr.mu.Unlock()

	return lsr.reportData
}

// DeleteReport deletes a report based on the report ID.
func (lsr *LoanServiceReporting) DeleteReport(reportID string) error {
	lsr.mu.Lock()
	defer lsr.mu.Unlock()

	for i, report := range lsr.reportData {
		if report.ID == reportID {
			// Delete the report file
			err := os.Remove(report.FilePath)
			if err != nil {
				return err
			}
			// Remove report data from slice
			lsr.reportData = append(lsr.reportData[:i], lsr.reportData[i+1:]...)
			return nil
		}
	}

	return errors.New("report not found")
}

// generateID generates a unique ID for reports.
func generateID() string {
	// Implement unique ID generation (e.g., UUID)
	return "unique-id-placeholder"
}
