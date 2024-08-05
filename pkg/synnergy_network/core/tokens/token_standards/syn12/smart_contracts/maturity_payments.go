package smart_contracts

import (
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/compliance"
)

// MaturityPayments manages the calculation and distribution of maturity payments for T-Bill tokens.
type MaturityPayments struct {
	Ledger     *ledger.TransactionLedger
	Compliance *compliance.ComplianceManager
}

// NewMaturityPayments initializes a new instance of MaturityPayments.
func NewMaturityPayments(ledger *ledger.TransactionLedger, compliance *compliance.ComplianceManager) *MaturityPayments {
	return &MaturityPayments{
		Ledger:     ledger,
		Compliance: compliance,
	}
}

// CalculateMaturityPayment calculates the maturity payment for a given T-Bill token.
func (mp *MaturityPayments) CalculateMaturityPayment(tokenID string) (float64, error) {
	tokenMetadata, err := mp.Ledger.GetTokenMetadata(tokenID)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve token metadata: %v", err)
	}

	principal := tokenMetadata.PrincipalAmount
	maturityPayment := principal // Assume full principal return at maturity
	return maturityPayment, nil
}

// DistributeMaturityPayment distributes the calculated maturity payment to the token holder.
func (mp *MaturityPayments) DistributeMaturityPayment(tokenID, userID string) error {
	// Ensure compliance checks are passed
	if err := mp.Compliance.PerformKYC(userID); err != nil {
		return fmt.Errorf("KYC compliance failed: %v", err)
	}

	// Calculate the maturity payment
	maturityPayment, err := mp.CalculateMaturityPayment(tokenID)
	if err != nil {
		return fmt.Errorf("failed to calculate maturity payment: %v", err)
	}

	// Record the maturity payment transaction
	err = mp.Ledger.RecordMaturityPayment(tokenID, userID, maturityPayment)
	if err != nil {
		return fmt.Errorf("failed to record maturity payment transaction: %v", err)
	}

	// Distribute the maturity payment (this could be more complex, involving actual transfer of funds)
	fmt.Printf("Distributed a maturity payment of %.2f to user %s for token %s\n", maturityPayment, userID, tokenID)

	return nil
}

// ScheduleMaturityPayments sets up a schedule for regular maturity payments based on the T-Bill's terms.
func (mp *MaturityPayments) ScheduleMaturityPayments(tokenID, userID string, maturityDate time.Time) error {
	// Validate inputs and compliance
	if err := mp.Compliance.PerformKYC(userID); err != nil {
		return fmt.Errorf("KYC compliance failed: %v", err)
	}

	// Example scheduling logic (this could use a more sophisticated scheduler)
	timeUntilMaturity := time.Until(maturityDate)
	timer := time.NewTimer(timeUntilMaturity)
	go func() {
		<-timer.C
		err := mp.DistributeMaturityPayment(tokenID, userID)
		if err != nil {
			fmt.Printf("Error distributing maturity payment: %v\n", err)
		}
	}()

	return nil
}

// AdjustMaturityPayment adjusts the payment amount if necessary, typically based on new policy or regulation.
func (mp *MaturityPayments) AdjustMaturityPayment(tokenID string, newAmount float64) error {
	// Retrieve and validate current token metadata
	tokenMetadata, err := mp.Ledger.GetTokenMetadata(tokenID)
	if err != nil {
		return fmt.Errorf("failed to retrieve token metadata: %v", err)
	}

	// Update the maturity payment amount in the ledger
	tokenMetadata.PrincipalAmount = newAmount
	err = mp.Ledger.UpdateTokenMetadata(tokenID, tokenMetadata)
	if err != nil {
		return fmt.Errorf("failed to update maturity payment amount: %v", err)
	}

	fmt.Printf("Maturity payment for token %s adjusted to %.2f\n", tokenID, newAmount)
	return nil
}
