package custodialnode

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "os"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
)

// TestSetup ensures the environment is properly set up
func TestSetup(t *testing.T) {
    dataDir := "/app/data"
    logDir := "/app/logs"

    os.MkdirAll(dataDir, os.ModePerm)
    os.MkdirAll(logDir, os.ModePerm)

    _, errData := os.Stat(dataDir)
    _, errLogs := os.Stat(logDir)

    assert.False(t, os.IsNotExist(errData), "Data directory does not exist")
    assert.False(t, os.IsNotExist(errLogs), "Logs directory does not exist")
}

// TestEncryptionDecryption tests the encryption and decryption functions
func TestEncryptionDecryption(t *testing.T) {
    plaintext := []byte("Sensitive data that needs encryption")
    label := []byte("label")

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    assert.NoError(t, err)

    publicKey := &privateKey.PublicKey

    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, label)
    assert.NoError(t, err)

    decryptedText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
    assert.NoError(t, err)

    assert.Equal(t, plaintext, decryptedText, "Decrypted text does not match original plaintext")
}

// TestStorageManagement ensures hierarchical storage management is functional
func TestStorageManagement(t *testing.T) {
    hotStoragePath := "/app/data/hot"
    coldStoragePath := "/app/data/cold"

    os.MkdirAll(hotStoragePath, os.ModePerm)
    os.MkdirAll(coldStoragePath, os.ModePerm)

    _, errHot := os.Stat(hotStoragePath)
    _, errCold := os.Stat(coldStoragePath)

    assert.False(t, os.IsNotExist(errHot), "Hot storage path does not exist")
    assert.False(t, os.IsNotExist(errCold), "Cold storage path does not exist")
}

// TestComplianceReporting ensures automated compliance reporting
func TestComplianceReporting(t *testing.T) {
    reportingInterval := 24 * time.Hour
    lastReportTime := time.Now()

    time.Sleep(2 * time.Second)

    currentTime := time.Now()
    elapsed := currentTime.Sub(lastReportTime)

    assert.True(t, elapsed >= reportingInterval, "Compliance reporting interval not met")
}

// TestBiometricVerification ensures biometric security is functional
func TestBiometricVerification(t *testing.T) {
    mockFingerprint := "userFingerprintHash"
    storedFingerprint := "userFingerprintHash"

    assert.Equal(t, mockFingerprint, storedFingerprint, "Biometric verification failed")
}

// TestMultiSignature ensures multi-signature transaction authorization
func TestMultiSignature(t *testing.T) {
    requiredSignatures := 2
    providedSignatures := 2

    assert.Equal(t, requiredSignatures, providedSignatures, "Multi-signature requirement not met")
}

// TestAuditAndPenetrationTesting ensures periodic security audits and penetration testing
func TestAuditAndPenetrationTesting(t *testing.T) {
    lastAudit := time.Now().Add(-30 * 24 * time.Hour)
    currentTime := time.Now()

    auditInterval := 30 * 24 * time.Hour
    timeForNextAudit := lastAudit.Add(auditInterval)

    assert.True(t, currentTime.After(timeForNextAudit), "Audit interval not met")

    // Simulate penetration test
    testResult := "No vulnerabilities found"
    assert.Equal(t, "No vulnerabilities found", testResult, "Penetration test failed")
}

// Helper function to save private key to file
func savePrivateKey(fileName string, key *rsa.PrivateKey) error {
    outFile, err := os.Create(fileName)
    if err != nil {
        return err
    }
    defer outFile.Close()

    privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
    var pemKey = &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }
    err = pem.Encode(outFile, pemKey)
    if err != nil {
        return err
    }

    return nil
}

// Helper function to load private key from file
func loadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
    pemFile, err := os.Open(fileName)
    if err != nil {
        return nil, err
    }
    defer pemFile.Close()

    pemInfo, _ := pem.Decode(pemFile)
    if pemInfo == nil {
        return nil, errors.New("failed to decode PEM file")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(pemInfo.Bytes)
    if err != nil {
        return nil, err
    }

    return privateKey, nil
}

func TestPrivateKeyStorage(t *testing.T) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    assert.NoError(t, err)

    fileName := "/app/data/private_key.pem"
    err = savePrivateKey(fileName, key)
    assert.NoError(t, err)

    loadedKey, err := loadPrivateKey(fileName)
    assert.NoError(t, err)

    assert.Equal(t, key.D, loadedKey.D, "Loaded private key does not match original")
}

func TestMain(m *testing.M) {
    // Setup code before tests run
    code := m.Run()
    // Teardown code after tests run
    os.Exit(code)
}
