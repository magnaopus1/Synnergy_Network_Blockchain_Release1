// Package reporting_and_visualization provides tools for reporting and visualizing smart contract audits.
package reporting_and_visualization

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/synnergy_network/core/crypto"
	"github.com/synnergy_network/core/models"
	"github.com/synnergy_network/core/utils"
)

// AuditReport defines the structure for storing audit report data.
type AuditReport struct {
	ContractName    string
	AuditTimestamp  time.Time
	Vulnerabilities []string
	Recommendations []string
	Status          string
}

// ReportManager handles the generation, storage, and management of audit reports.
type ReportManager struct {
	Reports         []AuditReport
	StoragePath     string
	NotificationURL string
}

// NewReportManager initializes a new ReportManager.
func NewReportManager(storagePath, notificationURL string) *ReportManager {
	return &ReportManager{
		Reports:         []AuditReport{},
		StoragePath:     storagePath,
		NotificationURL: notificationURL,
	}
}

// GenerateReport generates a detailed audit report for a given smart contract.
func (rm *ReportManager) GenerateReport(contract models.SmartContract, vulnerabilities, recommendations []string) (AuditReport, error) {
	log.Println("Generating audit report...")

	report := AuditReport{
		ContractName:    contract.Name,
		AuditTimestamp:  time.Now(),
		Vulnerabilities: vulnerabilities,
		Recommendations: recommendations,
		Status:          "Completed",
	}

	rm.Reports = append(rm.Reports, report)
	log.Printf("Audit report generated for contract: %s\n", contract.Name)
	return report, nil
}

// SaveReport saves the audit report to a file.
func (rm *ReportManager) SaveReport(report AuditReport) (string, error) {
	log.Println("Saving audit report...")

	fileName := fmt.Sprintf("%s_%s_audit_report.txt", report.ContractName, report.AuditTimestamp.Format("20060102_150405"))
	filePath := fmt.Sprintf("%s/%s", rm.StoragePath, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("error creating report file: %v", err)
	}
	defer file.Close()

	content := fmt.Sprintf("Smart Contract Audit Report - %s\n", report.AuditTimestamp)
	content += fmt.Sprintf("Contract: %s\n", report.ContractName)
	content += fmt.Sprintf("Vulnerabilities: %v\n", report.Vulnerabilities)
	content += fmt.Sprintf("Recommendations: %v\n", report.Recommendations)
	content += fmt.Sprintf("Status: %s\n", report.Status)

	_, err = file.WriteString(content)
	if err != nil {
		return "", fmt.Errorf("error writing to report file: %v", err)
	}

	log.Println("Audit report saved.")
	return filePath, nil
}

// EncryptReport encrypts the audit report using the provided key.
func (rm *ReportManager) EncryptReport(reportPath, key string) error {
	log.Println("Encrypting audit report...")

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("error reading report file: %v", err)
	}

	encryptedContent, err := crypto.EncryptAES(content, key)
	if err != nil {
		return fmt.Errorf("error encrypting report: %v", err)
	}

	err = os.WriteFile(reportPath, encryptedContent, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted report: %v", err)
	}

	log.Println("Audit report encrypted successfully.")
	return nil
}

// DecryptReport decrypts the audit report using the provided key.
func (rm *ReportManager) DecryptReport(reportPath, key string) error {
	log.Println("Decrypting audit report...")

	encryptedContent, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("error reading encrypted report file: %v", err)
	}

	decryptedContent, err := crypto.DecryptAES(encryptedContent, key)
	if err != nil {
		return fmt.Errorf("error decrypting report: %v", err)
	}

	err = os.WriteFile(reportPath, decryptedContent, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted report: %v", err)
	}

	log.Println("Audit report decrypted successfully.")
	return nil
}

// NotifyResults sends the audit results to the specified notification URL.
func (rm *ReportManager) NotifyResults(report AuditReport) error {
	log.Println("Notifying audit results...")

	notificationContent := fmt.Sprintf("Audit completed for contract: %s with status: %s\n", report.ContractName, report.Status)
	notificationContent += fmt.Sprintf("Vulnerabilities: %v\n", report.Vulnerabilities)
	notificationContent += fmt.Sprintf("Recommendations: %v\n", report.Recommendations)

	err := utils.SendNotification(rm.NotificationURL, notificationContent)
	if err != nil {
		return fmt.Errorf("error sending notification: %v", err)
	}

	log.Println("Audit results notification sent successfully.")
	return nil
}

// SaveAuditMetrics saves the audit metrics to a database for future analysis.
func (rm *ReportManager) SaveAuditMetrics(report AuditReport) error {
	log.Println("Saving audit metrics to database...")

	db, err := utils.ConnectToDatabase()
	if err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}
	defer db.Close()

	for _, vuln := range report.Vulnerabilities {
		err = db.SaveAuditMetric(vuln, report.AuditTimestamp)
		if err != nil {
			return fmt.Errorf("error saving audit metric: %v", err)
		}
	}

	log.Println("Audit metrics saved to database successfully.")
	return nil
}

// LoadReports loads all saved reports from the storage path.
func (rm *ReportManager) LoadReports() error {
	log.Println("Loading audit reports...")

	files, err := os.ReadDir(rm.StoragePath)
	if err != nil {
		return fmt.Errorf("error reading storage directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".txt" {
			content, err := os.ReadFile(filepath.Join(rm.StoragePath, file.Name()))
			if err != nil {
				return fmt.Errorf("error reading report file: %v", err)
			}

			var report AuditReport
			err = utils.ParseReportContent(content, &report)
			if err != nil {
				return fmt.Errorf("error parsing report content: %v", err)
			}

			rm.Reports = append(rm.Reports, report)
		}
	}

	log.Printf("Loaded %d audit reports.\n", len(rm.Reports))
	return nil
}

// ListReports lists all generated audit reports.
func (rm *ReportManager) ListReports() []AuditReport {
	return rm.Reports
}

// GetReport retrieves a specific audit report by contract name and timestamp.
func (rm *ReportManager) GetReport(contractName string, timestamp time.Time) (*AuditReport, error) {
	for _, report := range rm.Reports {
		if report.ContractName == contractName && report.AuditTimestamp.Equal(timestamp) {
			return &report, nil
		}
	}
	return nil, fmt.Errorf("report not found for contract: %s at %s", contractName, timestamp)
}
