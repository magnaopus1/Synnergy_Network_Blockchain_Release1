package geospatial_node

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "net"
    "os"
    "testing"
    "time"
)

const (
    testNodeID = "test-geospatial-node"
    testNodeAddress = "127.0.0.1:8081"
    testDatabasePath = "./testdata/geospatial.db"
    testLogDirectory = "./testdata/logs"
    testAuditTrailDirectory = "./testdata/audit"
    testEncryptionKey = "secure-test-encryption-key"
    testSalt = "test-salt"
)

var (
    testNode *GeospatialNode
)

func TestMain(m *testing.M) {
    // Setup: create necessary directories
    os.MkdirAll("./testdata", os.ModePerm)
    defer os.RemoveAll("./testdata")

    // Create and start test node
    storage := &FileSystemStorage{BasePath: "./testdata"}
    testNode = NewGeospatialNode(testNodeID, testNodeAddress, storage)
    go testNode.Start()
    defer testNode.Stop()

    // Run tests
    code := m.Run()

    // Teardown: stop the node and remove test data
    testNode.Stop()
    os.RemoveAll("./testdata")

    os.Exit(code)
}

func TestNodeInitialization(t *testing.T) {
    if testNode.ID != testNodeID {
        t.Errorf("Expected node ID %s, got %s", testNodeID, testNode.ID)
    }
    if testNode.NetworkAddress != testNodeAddress {
        t.Errorf("Expected node address %s, got %s", testNodeAddress, testNode.NetworkAddress)
    }
}

func TestStoreAndRetrieveData(t *testing.T) {
    sampleData := []byte("sample geospatial data")
    err := testNode.Storage.StoreData(sampleData)
    if err != nil {
        t.Fatalf("Failed to store data: %v", err)
    }

    storedData, err := testNode.Storage.RetrieveData("geospatial.db")
    if err != nil {
        t.Fatalf("Failed to retrieve data: %v", err)
    }
    if string(storedData) != string(sampleData) {
        t.Errorf("Retrieved data mismatch. Expected %s, got %s", string(sampleData), string(storedData))
    }
}

func TestHandleConnection(t *testing.T) {
    conn, err := net.Dial("tcp", testNodeAddress)
    if err != nil {
        t.Fatalf("Failed to connect to node: %v", err)
    }
    defer conn.Close()

    sampleData := "test geospatial transaction"
    _, err = conn.Write([]byte(sampleData))
    if err != nil {
        t.Fatalf("Failed to write data to node: %v", err)
    }
}

func TestEncryptionAndDecryption(t *testing.T) {
    data := []byte("test data for encryption")
    encryptedData, err := encryptData(data, testEncryptionKey, testSalt)
    if err != nil {
        t.Fatalf("Failed to encrypt data: %v", err)
    }

    decryptedData, err := decryptData(encryptedData, testEncryptionKey, testSalt)
    if err != nil {
        t.Fatalf("Failed to decrypt data: %v", err)
    }

    if string(decryptedData) != string(data) {
        t.Errorf("Decrypted data mismatch. Expected %s, got %s", string(data), string(decryptedData))
    }
}

func encryptData(data []byte, key string, salt string) ([]byte, error) {
    // Implement encryption logic (example using AES)
    return data, nil // Placeholder, replace with actual implementation
}

func decryptData(data []byte, key string, salt string) ([]byte, error) {
    // Implement decryption logic (example using AES)
    return data, nil // Placeholder, replace with actual implementation
}

func TestTLSConfiguration(t *testing.T) {
    certPEM, keyPEM := generateTestCert()
    if certPEM == nil || keyPEM == nil {
        t.Fatalf("Failed to generate test certificates")
    }

    certFile, err := os.Create("./testdata/test_cert.pem")
    if err != nil {
        t.Fatalf("Failed to create cert file: %v", err)
    }
    defer certFile.Close()
    keyFile, err := os.Create("./testdata/test_key.pem")
    if err != nil {
        t.Fatalf("Failed to create key file: %v", err)
    }
    defer keyFile.Close()

    certFile.Write(certPEM)
    keyFile.Write(keyPEM)

    // Implement TLS configuration logic
    // Placeholder: actual implementation needed
}

func generateTestCert() (certPEM, keyPEM []byte) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil
    }

    serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, nil
    }

    certTemplate := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"Test Org"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
    if err != nil {
        return nil, nil
    }

    certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
    keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
    return certPEM, keyPEM
}
