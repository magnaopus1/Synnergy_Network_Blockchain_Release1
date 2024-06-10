package centralized_control_tokens

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "io"
    "log"
    "time"

    "github.com/pkg/errors"
)

// MonetaryPolicy defines the structure for managing currency supply and interest rates.
type MonetaryPolicy struct {
    TokenID            string    `json:"token_id"`
    BaseInterestRate   float64   `json:"base_interest_rate"`   // Base rate for loans or savings
    ReserveRequirement float64   `json:"reserve_requirement"`  // Percentage of deposits to be held as reserves
    CurrencySupply     float64   `json:"currency_supply"`
    LastUpdated        time.Time `json:"last_updated"`
}

// PolicyEnforcer manages the application of monetary policies.
type PolicyEnforcer struct {
    policies       map[string]MonetaryPolicy
    encryptionKey  []byte
}

// NewPolicyEnforcer initializes a new PolicyEnforcer with a provided encryption key.
func NewPolicyEnforcer(key []byte) *PolicyEnforcer {
    return &PolicyEnforcer{
        policies:      make(map[string]MonetaryPolicy),
        encryptionKey: key,
    }
}

// SetMonetaryPolicy sets or updates a monetary policy for a specific token.
func (pe *PolicyEnforcer) SetMonetaryPolicy(tokenID string, policy MonetaryPolicy) error {
    pe.policies[tokenID] = policy
    log.Printf("Monetary policy updated for token: %s", tokenID)
    return nil
}

// GetMonetaryPolicy retrieves the monetary policy associated with a specific token.
func (pe *PolicyEnforcer) GetMonetaryPolicy(tokenID string) (MonetaryPolicy, error) {
    policy, exists := pe.policies[tokenID]
    if !exists {
        return MonetaryPolicy{}, errors.New("no monetary policy found for the specified token")
    }
    return policy, nil
}

// AdjustInterestRates dynamically adjusts interest rates based on economic conditions.
func (pe *PolicyEnforcer) AdjustInterestRates(tokenID string, delta float64) error {
    policy, exists := pe.policies[tokenID]
    if !exists {
        return errors.New("no monetary policy to adjust")
    }

    policy.BaseInterestRate += delta
    log.Printf("Adjusted interest rate for token %s: %f%%", tokenID, policy.BaseInterestRate)
    return pe.SetMonetaryPolicy(tokenID, policy)
}

// EncryptPolicies secures all monetary policies using AES encryption for safe storage or transmission.
func (pe *PolicyEnforcer) EncryptPolicies() ([]byte, error) {
    data, err := json.Marshal(pe.policies)
    if err != nil {
        return nil, errors.Wrap(err, "failed to marshal policies")
    }

    encryptedData, err := EncryptData(data, pe.encryptionKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to encrypt policies")
    }

    return encryptedData, nil
}

// DecryptPolicies decrypts the encrypted monetary policies data.
func (pe *PolicyEnforcer) DecryptPolicies(data []byte) error {
    decryptedData, err := DecryptData(data, pe.encryptionKey)
    if err != nil {
        return errors.Wrap(err, "failed to decrypt policies")
    }

    err = json.Unmarshal(decryptedData, &pe.policies)
    if err != nil {
        return errors.Wrap(err, "failed to unmarshal policies")
    }
    log.Println("Monetary policies decrypted and loaded successfully.")
    return nil
}

// EncryptData and DecryptData functions here utilize the Argon2 or AES-256 encryption methods, as specified.

