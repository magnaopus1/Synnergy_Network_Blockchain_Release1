package management

import (
    "errors"
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/assets"
    "github.com/synnergy_network/blockchain/ledger"
    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
    "github.com/synnergy_network/blockchain/payments"
)

// RentalPolicy defines a rental policy
type RentalPolicy struct {
    PolicyID         string
    CreatedAt        time.Time
    UpdatedAt        time.Time
    Description      string
    Rules            string
    Status           string
    RentalCost       float64
    LateFeePenalty   float64
    PaymentDueDate   time.Time
    GracePeriod      int // in days
}

// RentalPolicyManager handles rental policy management
type RentalPolicyManager struct {
    Ledger   ledger.Ledger
    Security security.Security
    Storage  storage.Storage
}

// NewRentalPolicyManager constructor
func NewRentalPolicyManager(ledger ledger.Ledger, security security.Security, storage storage.Storage) *RentalPolicyManager {
    return &RentalPolicyManager{
        Ledger:   ledger,
        Security: security,
        Storage:  storage,
    }
}

// CreatePolicy creates a new rental policy
func (rpm *RentalPolicyManager) CreatePolicy(description, rules string, rentalCost, lateFeePenalty float64, paymentDueDate time.Time, gracePeriod int) (string, error) {
    policyID := rpm.generatePolicyID()
    timestamp := time.Now()

    policy := RentalPolicy{
        PolicyID:       policyID,
        CreatedAt:      timestamp,
        UpdatedAt:      timestamp,
        Description:    description,
        Rules:          rules,
        Status:         "Active",
        RentalCost:     rentalCost,
        LateFeePenalty: lateFeePenalty,
        PaymentDueDate: paymentDueDate,
        GracePeriod:    gracePeriod,
    }

    if err := rpm.Storage.SavePolicy(policyID, policy); err != nil {
        return "", fmt.Errorf("error saving policy: %v", err)
    }

    return policyID, nil
}

// UpdatePolicy updates an existing rental policy
func (rpm *RentalPolicyManager) UpdatePolicy(policyID, description, rules string, rentalCost, lateFeePenalty float64, paymentDueDate time.Time, gracePeriod int) error {
    policy, err := rpm.GetPolicy(policyID)
    if err != nil {
        return err
    }

    policy.Description = description
    policy.Rules = rules
    policy.RentalCost = rentalCost
    policy.LateFeePenalty = lateFeePenalty
    policy.PaymentDueDate = paymentDueDate
    policy.GracePeriod = gracePeriod
    policy.UpdatedAt = time.Now()

    if err := rpm.Storage.SavePolicy(policyID, policy); err != nil {
        return fmt.Errorf("error updating policy: %v", err)
    }

    return nil
}

// GetPolicy retrieves a rental policy by its ID
func (rpm *RentalPolicyManager) GetPolicy(policyID string) (RentalPolicy, error) {
    policy, err := rpm.Storage.GetPolicy(policyID)
    if err != nil {
        return RentalPolicy{}, fmt.Errorf("error retrieving policy: %v", err)
    }

    return policy, nil
}

// DeletePolicy deletes a rental policy
func (rpm *RentalPolicyManager) DeletePolicy(policyID string) error {
    policy, err := rpm.GetPolicy(policyID)
    if err != nil {
        return err
    }

    policy.Status = "Deleted"
    policy.UpdatedAt = time.Now()

    if err := rpm.Storage.SavePolicy(policyID, policy); err != nil {
        return fmt.Errorf("error updating policy status: %v", err)
    }

    return nil
}

// EnforcePolicy enforces a rental policy
func (rpm *RentalPolicyManager) EnforcePolicy(policyID, tokenID string) error {
    policy, err := rpm.GetPolicy(policyID)
    if err != nil {
        return err
    }

    if policy.Status != "Active" {
        return errors.New("policy is not active")
    }

    agreement, err := rpm.Ledger.GetAgreement(tokenID)
    if err != nil {
        return fmt.Errorf("error retrieving agreement: %v", err)
    }

    // Implement policy enforcement logic here
    // For example, check agreement details against policy rules

    // Assuming a function to update agreement based on policy enforcement
    if err := rpm.Ledger.UpdateAgreement(tokenID, agreement); err != nil {
        return fmt.Errorf("error updating agreement: %v", err)
    }

    return nil
}

// ApplyLateFee applies late fee penalties to overdue payments
func (rpm *RentalPolicyManager) ApplyLateFee(tokenID string, paymentDate time.Time) error {
    agreement, err := rpm.Ledger.GetAgreement(tokenID)
    if err != nil {
        return fmt.Errorf("error retrieving agreement: %v", err)
    }

    policy, err := rpm.GetPolicy(agreement.PolicyID)
    if err != nil {
        return fmt.Errorf("error retrieving policy: %v", err)
    }

    if paymentDate.After(policy.PaymentDueDate.AddDate(0, 0, policy.GracePeriod)) {
        lateFee := policy.LateFeePenalty

        paymentRecord := payments.PaymentRecord{
            TokenID:   tokenID,
            Amount:    lateFee,
            Timestamp: paymentDate,
            Type:      "Late Fee",
        }

        if err := rpm.Ledger.StorePayment(tokenID, paymentRecord); err != nil {
            return fmt.Errorf("error storing late fee payment: %v", err)
        }

        agreement.PaymentHistory = append(agreement.PaymentHistory, paymentRecord)
        if err := rpm.Ledger.UpdateAgreement(tokenID, agreement); err != nil {
            return fmt.Errorf("error updating agreement with late fee: %v", err)
        }
    }

    return nil
}

// generatePolicyID generates a unique ID for a policy
func (rpm *RentalPolicyManager) generatePolicyID() string {
    return fmt.Sprintf("POLICY-%d", time.Now().UnixNano())
}
