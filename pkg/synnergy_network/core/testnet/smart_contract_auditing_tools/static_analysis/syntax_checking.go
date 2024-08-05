package static_analysis

import (
	"log"
	"regexp"
	"strings"

	"github.com/synnergy_network/core/models"
	"github.com/synnergy_network/core/utils"
)

// SyntaxChecker defines the structure for performing syntax checks on smart contracts.
type SyntaxChecker struct {
	Contracts []models.SmartContract
	Reports   []SyntaxCheckReport
}

// SyntaxCheckReport defines the structure for the report generated after checking a smart contract.
type SyntaxCheckReport struct {
	ContractName  string
	SyntaxIssues  []string
	LineIssues    map[int]string
}

// NewSyntaxChecker initializes a new SyntaxChecker.
func NewSyntaxChecker() *SyntaxChecker {
	return &SyntaxChecker{
		Contracts: []models.SmartContract{},
		Reports:   []SyntaxCheckReport{},
	}
}

// AddContract adds a smart contract to the syntax checker.
func (sc *SyntaxChecker) AddContract(contract models.SmartContract) {
	sc.Contracts = append(sc.Contracts, contract)
}

// CheckContracts performs syntax checking on all the added smart contracts.
func (sc *SyntaxChecker) CheckContracts() {
	log.Println("Performing syntax checks on smart contracts...")

	for _, contract := range sc.Contracts {
		report := sc.checkContract(contract)
		sc.Reports = append(sc.Reports, report)
	}

	log.Println("Syntax checks complete. Reports generated.")
}

// checkContract performs syntax checking on a single smart contract.
func (sc *SyntaxChecker) checkContract(contract models.SmartContract) SyntaxCheckReport {
	var syntaxIssues []string
	lineIssues := make(map[int]string)
	lines := strings.Split(contract.Code, "\n")

	for i, line := range lines {
		if strings.Contains(line, "TODO") {
			syntaxIssues = append(syntaxIssues, "Contains TODO comment.")
			lineIssues[i+1] = "TODO comment found."
		}

		if match, _ := regexp.MatchString(`\b(print|console.log)\b`, line); match {
			syntaxIssues = append(syntaxIssues, "Contains debug statements (print/console.log).")
			lineIssues[i+1] = "Debug statement found."
		}

		if match, _ := regexp.MatchString(`^\s*$`, line); match {
			syntaxIssues = append(syntaxIssues, "Contains empty lines.")
			lineIssues[i+1] = "Empty line found."
		}

		// Add additional syntax checks as required
	}

	return SyntaxCheckReport{
		ContractName: contract.Name,
		SyntaxIssues: syntaxIssues,
		LineIssues:   lineIssues,
	}
}

// GenerateReport generates a comprehensive report for all syntax-checked contracts.
func (sc *SyntaxChecker) GenerateReport() string {
	var report strings.Builder

	report.WriteString("Smart Contract Syntax Check Report\n")
	report.WriteString("===================================\n\n")

	for _, rpt := range sc.Reports {
		report.WriteString(fmt.Sprintf("Contract: %s\n", rpt.ContractName))
		report.WriteString("Syntax Issues:\n")
		if len(rpt.SyntaxIssues) == 0 {
			report.WriteString("  None\n")
		} else {
			for _, issue := range rpt.SyntaxIssues {
				report.WriteString(fmt.Sprintf("  - %s\n", issue))
			}
		}
		report.WriteString("Line Issues:\n")
		for line, issue := range rpt.LineIssues {
			report.WriteString(fmt.Sprintf("  Line %d: %s\n", line, issue))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// SaveReport saves the generated report to a file.
func (sc *SyntaxChecker) SaveReport(filePath string) error {
	report := sc.GenerateReport()
	return utils.WriteToFile(filePath, report)
}
