package transaction

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "log"
    "strconv"
    "strings"
    "time"
)



// NewBiometricTransaction creates a new biometric-secured transaction.
func (btm *common.BiometricTransactionManager) NewBiometricTransaction(sender, receiver string, amount float64, biometricData []byte) (*common.BiometricTransaction, error) {
    if sender == "" || receiver == "" || amount <= 0 {
        return nil, errors.New("invalid transaction parameters")
    }

    bioHash, err := generateBiometricHash(biometricData)
    if err != nil {
        return nil, err
    }

    txn := &common.BiometricTransaction{
        ID:             generateTransactionID(sender, receiver, amount),
        Sender:         sender,
        Receiver:       receiver,
        Amount:         amount,
        Timestamp:      time.Now(),
        BiometricHash:  bioHash,
        Status:         "Pending",
    }

    signature, err := signData(txn.ID + bioHash, sender)
    if err != nil {
        return nil, err
    }
    txn.DigitalSignature = signature

    return txn, nil
}

// ValidateBiometricTransaction validates a biometric-secured transaction.
func (btm *common.BiometricTransactionManager) ValidateBiometricTransaction(txn *common.BiometricTransaction, biometricData []byte) (bool, error) {
    validBio, err := verifyBiometricHash(txn.BiometricHash, biometricData)
    if err != nil || !validBio {
        return false, errors.New("biometric verification failed")
    }

    validSig, err := verifySignature(txn.DigitalSignature, txn.ID+txn.BiometricHash, txn.Sender)
    if err != nil || !validSig {
        return false, errors.New("digital signature verification failed")
    }

    if err := validateTransactionDetails(txn.Sender, txn.Receiver, txn.Amount); err != nil {
        return false, err
    }

    txn.Status = "Validated"
    return true, nil
}

// EncryptTransaction encrypts the transaction details using AES.
func (btm *common.BiometricTransactionManager) EncryptBiometricTransaction(txn *common.BiometricTransaction, encryptionKey []byte) (string, error) {
    txnData := txn.Sender + txn.Receiver + strconv.FormatFloat(txn.Amount, 'f', 6, 64) + txn.Timestamp.String() + txn.BiometricHash + txn.DigitalSignature
    encryptedData, err := encryptAES([]byte(txnData), encryptionKey)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptTransaction decrypts the encrypted transaction details.
func (btm *common.BiometricTransactionManager) DecryptBiometricTransaction(encryptedData string, encryptionKey []byte) (*common.BiometricTransaction, error) {
    decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    decryptedData, err := decryptAES(decodedData, encryptionKey)
    if err != nil {
        return nil, err
    }

    data := string(decryptedData)
    parts := strings.Split(data, "|")
    if len(parts) != 6 {
        return nil, errors.New("invalid decrypted data format")
    }
    amount, _ := strconv.ParseFloat(parts[2], 64)
    timestamp, _ := time.Parse(time.RFC3339, parts[3])
    txn := &common.BiometricTransaction{
        Sender:          parts[0],
        Receiver:        parts[1],
        Amount:          amount,
        Timestamp:       timestamp,
        BiometricHash:   parts[4],
        DigitalSignature: parts[5],
    }
    return txn, nil
}

// ProcessTransaction processes the validated transaction and updates the ledger.
func (btm *common.BiometricTransactionManager) ProcessBiometricTransaction(txn *common.BiometricTransaction) error {
    if txn.Status != "Validated" {
        return errors.New("transaction not validated")
    }

    if err := updateLedger(txn.Sender, txn.Receiver, txn.Amount); err != nil {
        return err
    }

    txn.Status = "Completed"
    logTransaction(txn.ID, txn.Status)
    return nil
}

// SimulateBiometricTransactions simulates a batch of biometric transactions.
func (btm *common.BiometricTransactionManager) SimulateBiometricTransactions(transactions []common.BiometricTransaction) error {
    for _, txn := range transactions {
        if _, err := btm.ValidateBiometricTransaction(&txn, nil); err != nil {
            return err
        }
        if err := btm.ProcessTransaction(&txn); err != nil {
            return err
        }
    }
    return nil
}



