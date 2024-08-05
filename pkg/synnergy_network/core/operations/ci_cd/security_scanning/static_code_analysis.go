package security_scanning

import (
	"log"
	"os/exec"
	"strings"
	"sync"
	"github.com/synnergy_network/pkg/synnergy_network/core/operations/ci_cd/utils"
	"github.com/synnergy_network/pkg/synnergy_network/core/operations/ci_cd/security_scanning/alerting"
	"github.com/synnergy_network/pkg/synnergy_network/core/operations/ci_cd/security_scanning/reporting"
)

// DependencyScanner defines the structure for dependency scanning
type DependencyScanner struct {
	mu sync.Mutex
	scanResults map[string]ScanResult
	alertingService alerting.AlertingService
	reportingService reporting.ReportingService
}

// ScanResult defines the structure of scan results
type ScanResult struct {
	PackageName  string
	Version      string
	Vulnerabilities []string
}

// NewDependencyScanner initializes a new DependencyScanner
func NewDependencyScanner() *DependencyScanner {
	return &DependencyScanner{
		scanResults: make(map[string]ScanResult),
		alertingService: alerting.NewAlertingService(),
		reportingService: reporting.NewReportingService(),
	}
}

// ScanDependencies performs the dependency scan
func (ds *DependencyScanner) ScanDependencies(projectPath string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	log.Println("Starting dependency scan...")

	// Using a placeholder command to represent the dependency scanning tool
	cmd := exec.Command("dependency-scanner", projectPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error executing dependency scanner: %s\n", err)
		return err
	}

	results := parseScanOutput(string(output))
	ds.processScanResults(results)

	log.Println("Dependency scan completed.")
	return nil
}

// parseScanOutput parses the output of the scan command
func parseScanOutput(output string) []ScanResult {
	lines := strings.Split(output, "\n")
	var results []ScanResult

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			continue
		}

		results = append(results, ScanResult{
			PackageName:  parts[0],
			Version:      parts[1],
			Vulnerabilities: strings.Split(parts[2], ","),
		})
	}
	return results
}

// processScanResults processes the scan results
func (ds *DependencyScanner) processScanResults(results []ScanResult) {
	for _, result := range results {
		ds.scanResults[result.PackageName] = result

		if len(result.Vulnerabilities) > 0 {
			ds.alertingService.SendAlert(result.PackageName, result.Version, result.Vulnerabilities)
		}
	}

	ds.reportingService.GenerateReport(ds.scanResults)
}

// AlertingService defines methods for sending alerts
package alerting

import (
	"log"
)

type AlertingService struct{}

// NewAlertingService initializes a new AlertingService
func NewAlertingService() *AlertingService {
	return &AlertingService{}
}

// SendAlert sends an alert for a vulnerable package
func (as *AlertingService) SendAlert(packageName, version string, vulnerabilities []string) {
	alertMessage := formatAlertMessage(packageName, version, vulnerabilities)
	log.Println(alertMessage)
	// Additional logic for sending alert (e.g., email, Slack) can be added here
}

// formatAlertMessage formats the alert message
func formatAlertMessage(packageName, version string, vulnerabilities []string) string {
	return "Vulnerability Alert: " + packageName + "@" + version + " - Vulnerabilities: " + strings.Join(vulnerabilities, ", ")
}

// ReportingService defines methods for generating reports
package reporting

import (
	"log"
	"os"
	"encoding/json"
)

type ReportingService struct{}

// NewReportingService initializes a new ReportingService
func NewReportingService() *ReportingService {
	return &ReportingService{}
}

// GenerateReport generates a report from scan results
func (rs *ReportingService) GenerateReport(scanResults map[string]ScanResult) {
	file, err := os.Create("dependency_scan_report.json")
	if err != nil {
		log.Printf("Error creating report file: %s\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(scanResults); err != nil {
		log.Printf("Error encoding scan results: %s\n", err)
	}
	log.Println("Dependency scan report generated.")
}
