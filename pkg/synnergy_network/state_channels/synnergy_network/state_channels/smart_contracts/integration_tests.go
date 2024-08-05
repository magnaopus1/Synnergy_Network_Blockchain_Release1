package smart_contracts

import (
    "testing"
    "time"
    "crypto/rand"
    "github.com/stretchr/testify/assert"
)

func TestAutomatedSettlement(t *testing.T) {
    key, salt := setupEncryption()
    as := NewAutomatedSettlement("settle-001", "contract-001")

    // Test Completion
    err := as.CompleteSettlement("All conditions met")
    assert.NoError(t, err)
    assert.Equal(t, SetCompleted, as.Status)

    // Encrypt and Decrypt
    encData, err := as.EncryptSettlement(key)
    assert.NoError(t, err)
    newAS := &AutomatedSettlement{}
    err = newAS.DecryptSettlement(encData, key)
    assert.NoError(t, err)
    assert.Equal(t, as.String(), newAS.String())
}

func TestConditionalPayment(t *testing.T) {
    key, salt := setupEncryption()
    cp := NewConditionalPayment("payment-001", "contract-002", "Condition XYZ")

    // Test Completion
    err := cp.CompletePayment("Condition XYZ met")
    assert.NoError(t, err)
    assert.Equal(t, PayCompleted, cp.Status)

    // Encrypt and Decrypt
    encData, err := cp.EncryptPayment(key)
    assert.NoError(t, err)
    newCP := &ConditionalPayment{}
    err = newCP.DecryptPayment(encData, key)
    assert.NoError(t, err)
    assert.Equal(t, cp.String(), newCP.String())
}

func setupEncryption() ([]byte, []byte) {
    password := []byte("securepassword")
    salt, err := GenerateSalt()
    if err != nil {
        panic(err)
    }
    key := GenerateKey(password, salt)
    return key, salt
}
