// Package static_analysis provides tools for performing static analysis on smart contracts to ensure best practices.
package static_analysis

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/synnergy_network/core/models"
	"github.com/synnergy_network/core/utils"
)

// BestPracticesAnalyzer defines the structure for analyzing best practices in smart contracts.
type BestPracticesAnalyzer struct {
	Contracts []models.SmartContract
	Reports   []BestPracticesReport
}

// BestPracticesReport defines the structure for the report generated after analyzing a smart contract.
type BestPracticesReport struct {
	ContractName      string
	SecurityIssues    []string
	EfficiencyIssues  []string
	MaintainabilityIssues []string
}

// NewBestPracticesAnalyzer initializes a new BestPracticesAnalyzer.
func NewBestPracticesAnalyzer() *BestPracticesAnalyzer {
	return &BestPracticesAnalyzer{
		Contracts: []models.SmartContract{},
		Reports:   []BestPracticesReport{},
	}
}

// AddContract adds a smart contract to the analyzer.
func (bpa *BestPracticesAnalyzer) AddContract(contract models.SmartContract) {
	bpa.Contracts = append(bpa.Contracts, contract)
}

// AnalyzeContracts analyzes all the added smart contracts for best practices.
func (bpa *BestPracticesAnalyzer) AnalyzeContracts() {
	log.Println("Analyzing smart contracts for best practices...")

	for _, contract := range bpa.Contracts {
		report := bpa.analyzeContract(contract)
		bpa.Reports = append(bpa.Reports, report)
	}

	log.Println("Analysis complete. Reports generated.")
}

// analyzeContract analyzes a single smart contract for best practices.
func (bpa *BestPracticesAnalyzer) analyzeContract(contract models.SmartContract) BestPracticesReport {
	var securityIssues, efficiencyIssues, maintainabilityIssues []string

	// Security Analysis
	if !strings.Contains(contract.Code, "revert") && !strings.Contains(contract.Code, "require") {
		securityIssues = append(securityIssues, "Missing error handling mechanisms (revert/require).")
	}

	re := regexp.MustCompile(`call.value\([^)]*\)\(`)
	if re.MatchString(contract.Code) {
		securityIssues = append(securityIssues, "Use of call.value(), consider using transfer() or send() instead.")
	}

	// Efficiency Analysis
	if strings.Contains(contract.Code, "for (") || strings.Contains(contract.Code, "while (") {
		efficiencyIssues = append(efficiencyIssues, "Potentially unbounded loop detected, which can lead to high gas costs.")
	}

	// Maintainability Analysis
	if strings.Count(contract.Code, "\n") > 500 {
		maintainabilityIssues = append(maintainabilityIssues, "Contract length exceeds 500 lines, consider modularizing the code.")
	}

	return BestPracticesReport{
		ContractName:        contract.Name,
		SecurityIssues:      securityIssues,
		EfficiencyIssues:    efficiencyIssues,
		MaintainabilityIssues: maintainabilityIssues,
	}
}

// GenerateReport generates a comprehensive report for all analyzed contracts.
func (bpa *BestPracticesAnalyzer) GenerateReport() string {
	var report strings.Builder

	report.WriteString("Smart Contract Best Practices Analysis Report\n")
	report.WriteString("===========================================\n\n")

	for _, rpt := range bpa.Reports {
		report.WriteString(fmt.Sprintf("Contract: %s\n", rpt.ContractName))
		report.WriteString("Security Issues:\n")
		if len(rpt.SecurityIssues) == 0 {
			report.WriteString("  None\n")
		} else {
			for _, issue := range rpt.SecurityIssues {
				report.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
		report.WriteString("Efficiency Issues:\n")
		if len(rpt.EfficiencyIssues) == 0 {
			report.WriteString("  None\n")
		} else {
			for _, issue := range rpt.EfficiencyIssues {
				report.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
		report.WriteString("Maintainability Issues:\n")
		if len(rpt.MaintainabilityIssues) == 0 {
			report.WriteString("  None\n")
		} else {
			for _, issue := range rpt.MaintainabilityIssues {
				report.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
		report.WriteString("\n")
	}

	return report.String()
}

// SaveReport saves the generated report to a file.
func (bpa *BestPracticesAnalyzer) SaveReport(filePath string) error {
	report := bpa.GenerateReport()
	return utils.WriteToFile(filePath, report)
}
