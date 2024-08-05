// Package integration_and_automation provides tools for integrating and automating smart contract auditing.
package integration_and_automation

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/synnergy_network/core/crypto"
	"github.com/synnergy_network/core/models"
	"github.com/synnergy_network/core/utils"
)

// CI_CDIntegration defines the structure for CI/CD integration of smart contract auditing tools.
type CI_CDIntegration struct {
	RepoURL         string
	Branch          string
	AuditResults    AuditResults
	NotificationURL string
}

// AuditResults stores the results of the audit.
type AuditResults struct {
	Vulnerabilities []string
	Recommendations []string
	Timestamp       time.Time
	Status          string
}

// NewCI_CDIntegration initializes a new CI_CDIntegration.
func NewCI_CDIntegration(repoURL, branch, notificationURL string) *CI_CDIntegration {
	return &CI_CDIntegration{
		RepoURL:         repoURL,
		Branch:          branch,
		NotificationURL: notificationURL,
		AuditResults: AuditResults{
			Vulnerabilities: []string{},
			Recommendations: []string{},
			Timestamp:       time.Now(),
			Status:          "Pending",
		},
	}
}

// CloneRepository clones the smart contract repository.
func (ci *CI_CDIntegration) CloneRepository() error {
	log.Println("Cloning repository...")

	cloneCmd := exec.Command("git", "clone", "-b", ci.Branch, ci.RepoURL, "/tmp/smart_contract_repo")
	cloneOutput, err := cloneCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error cloning repository: %v, output: %s", err, cloneOutput)
	}

	log.Println("Repository cloned successfully.")
	return nil
}

// RunAudits runs the smart contract audits.
func (ci *CI_CDIntegration) RunAudits() error {
	log.Println("Running smart contract audits...")

	contractFiles, err := utils.GetSmartContractFiles("/tmp/smart_contract_repo")
	if err != nil {
		return fmt.Errorf("error getting smart contract files: %v", err)
	}

	for _, file := range contractFiles {
		log.Printf("Auditing file: %s\n", file)
		auditTool := NewSecurityTestingTool(file)
		err := auditTool.AnalyzeSecurity()
		if err != nil {
			return fmt.Errorf("error analyzing security: %v", err)
		}

		ci.AuditResults.Vulnerabilities = append(ci.AuditResults.Vulnerabilities, auditTool.AnalysisResults.Vulnerabilities...)
		ci.AuditResults.Recommendations = append(ci.AuditResults.Recommendations, auditTool.AnalysisResults.Recommendations...)
	}

	ci.AuditResults.Timestamp = time.Now()
	ci.AuditResults.Status = "Completed"
	log.Println("Smart contract audits completed.")
	return nil
}

// GenerateAuditReport generates a detailed audit report.
func (ci *CI_CDIntegration) GenerateAuditReport(outputPath string) error {
	log.Println("Generating audit report...")

	reportFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating report file: %v", err)
	}
	defer reportFile.Close()

	// Generate report content
	reportContent := fmt.Sprintf("Smart Contract Audit Report - %s\n", ci.AuditResults.Timestamp)
	reportContent += fmt.Sprintf("Vulnerabilities: %v\n", ci.AuditResults.Vulnerabilities)
	reportContent += fmt.Sprintf("Recommendations: %v\n", ci.AuditResults.Recommendations)
	reportContent += fmt.Sprintf("Status: %s\n", ci.AuditResults.Status)

	_, err = reportFile.WriteString(reportContent)
	if err != nil {
		return fmt.Errorf("error writing to report file: %v", err)
	}

	log.Println("Audit report generated.")
	return nil
}

// EncryptReport encrypts the audit report using the provided key.
func (ci *CI_CDIntegration) EncryptReport(reportPath, key string) error {
	log.Println("Encrypting report...")

	reportContent, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("error reading report file: %v", err)
	}

	encryptedContent, err := crypto.EncryptAES(reportContent, key)
	if err != nil {
		return fmt.Errorf("error encrypting report: %v", err)
	}

	err = os.WriteFile(reportPath, encryptedContent, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted report: %v", err)
	}

	log.Println("Report encrypted successfully.")
	return nil
}

// DecryptReport decrypts the audit report using the provided key.
func (ci *CI_CDIntegration) DecryptReport(reportPath, key string) error {
	log.Println("Decrypting report...")

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

	log.Println("Report decrypted successfully.")
	return nil
}

// NotifyResults sends the audit results to the specified notification URL.
func (ci *CI_CDIntegration) NotifyResults() error {
	log.Println("Notifying audit results...")

	// Placeholder for sending notifications (e.g., via HTTP POST request)
	notificationContent := fmt.Sprintf("Audit completed with status: %s\n", ci.AuditResults.Status)
	notificationContent += fmt.Sprintf("Vulnerabilities: %v\n", ci.AuditResults.Vulnerabilities)
	notificationContent += fmt.Sprintf("Recommendations: %v\n", ci.AuditResults.Recommendations)

	err := utils.SendNotification(ci.NotificationURL, notificationContent)
	if err != nil {
		return fmt.Errorf("error sending notification: %v", err)
	}

	log.Println("Audit results notification sent successfully.")
	return nil
}

// SaveAuditMetrics saves the audit metrics to a database for future analysis.
func (ci *CI_CDIntegration) SaveAuditMetrics() error {
	log.Println("Saving audit metrics to database...")

	db, err := utils.ConnectToDatabase()
	if err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}
	defer db.Close()

	for _, vuln := range ci.AuditResults.Vulnerabilities {
		err = db.SaveAuditMetric(vuln, ci.AuditResults.Timestamp)
		if err != nil {
			return fmt.Errorf("error saving audit metric: %v", err)
		}
	}

	log.Println("Audit metrics saved to database successfully.")
	return nil
}
