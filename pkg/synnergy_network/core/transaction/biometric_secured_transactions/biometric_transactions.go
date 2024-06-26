package biometric_secured_transactions

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"

    "synthron/blockchain"
    "synthron/crypto"
)

// BiometricTransactionManager handles transactions secured by biometric data.
type BiometricTransactionManager struct {
    BiometricDB map[string]string // Simulates a database of biometric hashes.
}

// NewBiometricTransactionManager creates a new instance of BiometricTransactionManager.
func NewBiometricTransactionManager() *BiometricTransactionManager {
    return &BiometricTransactionManager{
        BiometricDB: make(map[string]string),
    }
}

// RegisterBiometricData hashes and stores biometric data associated with a userID.
func (btm *BiometricTransactionManager) RegisterBiometricData(userID string, biometricData []byte) error {
    hashedData := sha256.Sum256(biometricData)
    btm.BiometricDB[userID] = hex.EncodeToString(hashedData[:])
    fmt.Printf("Biometric data registered for user %s\n", userID)
    return nil
}

// VerifyBiometricData checks if the provided biometric data matches the stored hash for the userID.
func (btm *BiometricTransactionManager) VerifyBiometricData(userID string, biometricData []byte) (bool, error) {
    hashedData := sha256.Sum256(biometricData)
    encodedData := hex.EncodeToString(hashedData[:])
    if btm.BiometricDB[userID] != encodedData {
        return false, errors.New("biometric verification failed")
    }
    fmt.Printf("Biometric data verified for user %s\n", userID)
    return true, nil
}

// CreateBiometricSecuredTransaction creates and signs a transaction if biometric verification is successful.
func (btm *BiometricTransactionManager) CreateBiometricSecuredTransaction(userID string, biometricData []byte, tx blockchain.Transaction) (blockchain.Transaction, error) {
    verified, err := btm.VerifyBiometricData(userID, biometricData)
    if err != nil || !verified {
        return blockchain.Transaction{}, errors.New("failed to verify biometric data, transaction aborted")
    }

    // Sign the transaction with user's private key (simulation)
    privateKey, _ := crypto.GeneratePrivateKey()
    signedTx, err := crypto.SignTransaction(tx, privateKey)
    if err != nil {
        return blockchain.Transaction{}, fmt.Errorf("failed to sign transaction: %v", err)
    }

    fmt.Println("Transaction successfully created and signed using biometric verification.")
    return signedTx, nil
}

