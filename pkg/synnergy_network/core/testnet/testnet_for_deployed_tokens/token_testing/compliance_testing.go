package token_testing

import (
	"errors"
	"fmt"
	"log"

	"github.com/synnergy_network/core/token_standards/syn20"
	"github.com/synnergy_network/core/token_standards/syn70"
	"github.com/synnergy_network/core/token_standards/syn120"
	"github.com/synnergy_network/core/token_standards/syn3000"
)

// TokenType defines the structure for various token standards.
type TokenType string

const (
	Syn20   TokenType = "Syn20"
	Syn70   TokenType = "Syn70"
	Syn120  TokenType = "Syn120"
	Syn3000 TokenType = "Syn3000"
	// Add additional token standards as needed.
)

// ComplianceTester holds the methods for compliance testing.
type ComplianceTester struct{}

// NewComplianceTester creates a new instance of ComplianceTester.
func NewComplianceTester() *ComplianceTester {
	return &ComplianceTester{}
}

// ComplianceResult holds the result of a compliance test.
type ComplianceResult struct {
	TokenID   string
	TokenType TokenType
	Compliant bool
	Issues    []string
}

// TestCompliance runs a compliance test on a given token.
func (ct *ComplianceTester) TestCompliance(tokenID string, tokenType TokenType) (ComplianceResult, error) {
	var compliant bool
	var issues []string

	switch tokenType {
	case Syn20:
		compliant, issues = syn20.CheckCompliance(tokenID)
	case Syn70:
		compliant, issues = syn70.CheckCompliance(tokenID)
	case Syn120:
		compliant, issues = syn120.CheckCompliance(tokenID)
	case Syn3000:
		compliant, issues = syn3000.CheckCompliance(tokenID)
	default:
		return ComplianceResult{}, errors.New("unsupported token type")
	}

	result := ComplianceResult{
		TokenID:   tokenID,
		TokenType: tokenType,
		Compliant: compliant,
		Issues:    issues,
	}

	return result, nil
}

// LogComplianceResult logs the result of the compliance test.
func (ct *ComplianceTester) LogComplianceResult(result ComplianceResult) {
	log.Printf("Compliance Test Result for TokenID: %s, TokenType: %s", result.TokenID, result.TokenType)
	log.Printf("Compliant: %v", result.Compliant)
	if len(result.Issues) > 0 {
		log.Printf("Issues: %v", result.Issues)
	} else {
		log.Println("No Issues Found")
	}
}

// CheckComplianceForAllTokens checks compliance for all tokens in the system.
func (ct *ComplianceTester) CheckComplianceForAllTokens(tokens map[string]TokenType) []ComplianceResult {
	var results []ComplianceResult

	for tokenID, tokenType := range tokens {
		result, err := ct.TestCompliance(tokenID, tokenType)
		if err != nil {
			log.Printf("Error testing compliance for TokenID: %s, TokenType: %s. Error: %v", tokenID, tokenType, err)
			continue
		}
		ct.LogComplianceResult(result)
		results = append(results, result)
	}

	return results
}

// GenerateComplianceReport generates a comprehensive compliance report.
func (ct *ComplianceTester) GenerateComplianceReport(results []ComplianceResult) {
	fmt.Println("Compliance Report")
	fmt.Println("=================")
	for _, result := range results {
		fmt.Printf("TokenID: %s, TokenType: %s, Compliant: %v\n", result.TokenID, result.TokenType, result.Compliant)
		if len(result.Issues) > 0 {
			fmt.Printf("Issues: %v\n", result.Issues)
		} else {
			fmt.Println("No Issues Found")
		}
		fmt.Println("-----------------")
	}
}

// main logic to execute compliance testing, assuming tokens map contains all token ids and their types
func main() {
	tokens := map[string]TokenType{
		"tokenID1": Syn20,
		"tokenID2": Syn70,
		"tokenID3": Syn120,
		"tokenID4": Syn3000,
	}

	complianceTester := NewComplianceTester()
	results := complianceTester.CheckComplianceForAllTokens(tokens)
	complianceTester.GenerateComplianceReport(results)
}
