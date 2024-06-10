package biometric_secured_transactions

import (
    "errors"
    "synthron/blockchain"
    "synthron/security"
)

// BiometricModule manages the biometric data verification and transaction validation.
type BiometricModule struct {
    BiometricStorage security.BiometricStorage
    CryptoService    security.CryptographyService
}

// NewBiometricModule creates a new instance of BiometricModule with necessary dependencies.
func NewBiometricModule(storage security.BiometricStorage, cryptoService security.CryptographyService) *BiometricModule {
    return &BiometricModule{
        BiometricStorage: storage,
        CryptoService:    cryptoService,
    }
}

// EnrollBiometricData handles the enrollment of new biometric data into the system.
func (bm *BiometricModule) EnrollBiometricData(userID string, biometricData []byte) error {
    if len(biometricData) == 0 {
        return errors.New("biometric data cannot be empty")
    }

    // Encrypt biometric data before storing
    encryptedData, err := bm.CryptoService.EncryptData(biometricData)
    if err != nil {
        return err
    }

    return bm.BiometricStorage.StoreBiometricData(userID, encryptedData)
}

// VerifyBiometricData checks the provided biometric data against the stored version.
func (bm *BiometricModule) VerifyBiometricData(userID string, biometricData []byte) (bool, error) {
    storedData, err := bm.BiometricStorage.RetrieveBiometricData(userID)
    if err != nil {
        return false, err
    }

    decryptedData, err := bm.CryptoService.DecryptData(storedData)
    if err != nil {
        return false, err
    }

    // Perform comparison
    return bm.CryptoService.CompareData(decryptedData, biometricData), nil
}

// AuthorizeTransaction verifies biometric data and authorizes a blockchain transaction.
func (bm *BiometricModule) AuthorizeTransaction(tx blockchain.Transaction, userID string, biometricData []byte) (bool, error) {
    valid, err := bm.VerifyBiometricData(userID, biometricData)
    if err != nil {
        return false, err
    }
    if !valid {
        return false, errors.New("biometric verification failed")
    }

    // Proceed with transaction processing if biometric data is verified
    return true, bm.processTransaction(tx)
}

// processTransaction encapsulates the logic to process transactions securely.
func (bm *BiometricModule) processTransaction(tx blockchain.Transaction) error {
    // Implementation for processing the transaction
    return nil // Placeholder return
}
