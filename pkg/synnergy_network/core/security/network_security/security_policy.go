package security

import (
    "log"
    "time"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

const (
    Salt       = "secure-salt"
    KeyLength  = 32
)

// SecurityPolicy defines the structure for organization's security policies.
type SecurityPolicy struct {
    PolicyID     string
    Description  string
    LastReviewed time.Time
}

// UpdatePolicyDetails updates the details of a given security policy.
func (sp *SecurityPolicy) UpdatePolicyDetails(description string) {
    sp.Description = description
    sp.LastReviewed = time.Now()
    log.Printf("Updated policy %s on %s", sp.PolicyID, sp.LastReviewed)
}

// EncryptPolicyData secures sensitive policy data using Argon2.
func EncryptPolicyData(data string) string {
    salt := []byte(Salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, KeyLength)
    return string(hash)
}

// DecryptPolicyData simulates decryption process for demonstration using Scrypt.
func DecryptPolicyData(data string) ([]byte, error) {
    salt := []byte(Salt)
    key, err := scrypt.Key([]byte(data), salt, 16384, 8, 1, KeyLength)
    if err != nil {
        return nil, err
    }
    return key, nil
}

// CreatePolicy initializes a new security policy with the given ID and description.
func CreatePolicy(id, description string) *SecurityPolicy {
    return &SecurityPolicy{
        PolicyID:     id,
        Description:  description,
        LastReviewed: time.Now(),
    }
}

// Main function to demonstrate creation and updating of security policies
func main() {
    // Example creation of a new security policy
    policy := CreatePolicy("SP001", "Initial Security Policy for handling sensitive data.")
    log.Printf("Created new security policy: %s - %s", policy.PolicyID, policy.Description)

    // Update and encrypt policy details
    policy.UpdatePolicyDetails("Updated Security Policy to include new standards for data encryption.")
    encryptedData := EncryptPolicyData(policy.Description)
    log.Printf("Policy updated and data encrypted: %s", encryptedData)
}
