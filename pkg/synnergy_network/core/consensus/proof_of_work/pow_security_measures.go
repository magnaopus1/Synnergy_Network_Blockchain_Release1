package consensus

import (
    "crypto/sha256"
    "encoding/hex"
    "math/big"
    "sync"
    "time"
	"net"
)

// SecurityMeasures manages the security aspects of the PoW consensus mechanism
type SecurityMeasures struct {
    Blockchain *Blockchain
    lock       sync.Mutex
}

// NewSecurityMeasures initializes a new instance of security management
func NewSecurityMeasures(blockchain *Blockchain) *SecurityMeasures {
    return &SecurityMeasures{
        Blockchain: blockchain,
    }
}

// ValidateBlockHash ensures that a block's hash meets the network's difficulty criteria
func (sm *SecurityMeasures) ValidateBlockHash(block *Block) bool {
    sm.lock.Lock()
    defer sm.lock.Unlock()

    target := sm.getCurrentTarget()
    hashInt := new(big.Int)
    hashInt.SetBytes(block.Hash)

    // Block is valid if hash is less than the current target
    return hashInt.Cmp(target) == -1
}

// getCurrentTarget computes the target hash based on the current network difficulty
func (sm *SecurityMeasures) getCurrentTarget() *big.Int {
    // The target is recalculated by shifting a base value according to the blockchain's difficulty
    return big.NewInt(1).Lsh(big.NewInt(1), uint(256-sm.Blockchain.Difficulty))
}

// MonitorNetworkHealth performs real-time checks and statistics on network operations
func (sm *SecurityMeasures) MonitorNetworkHealth() {
    // Example: Detect and log anomalies in block arrival times
    var lastBlockTime int64
    for _, block := range sm.Blockchain.Blocks {
        if lastBlockTime != 0 && (block.Timestamp-lastBlockTime > int64(2*sm.Blockchain.BlockTime)) {
            // Log anomaly
            sm.logAnomaly("Block time deviation detected", block)
        }
        lastBlockTime = block.Timestamp
    }
}

// logAnomaly helps in logging unexpected behaviors or potential security breaches
func (sm *SecurityMeasures) logAnomaly(message string, block *Block) {
    // Implement a logging mechanism for anomalies
    // This is a placeholder for integrating with a real logging system
    println("Anomaly detected:", message, "at block", block.Hash)
}

// ProtectAgainstDoubleSpending ensures that there are no duplicate transactions within the network
func (sm *SecurityMeasures) ProtectAgainstDoubleSpending(block *Block) bool {
    seenTransactions := make(map[string]bool)
    for _, tx := range block.Transactions {
        if _, exists := seenTransactions[tx.ID]; exists {
            return false
        }
        seenTransactions[tx.ID] = true
    }
    return true
}

// VerifyTransactionIntegrity checks the integrity and signatures of transactions
func (sm *SecurityMeasures) VerifyTransactionIntegrity(tx *Transaction) bool {
    // Decode the sender's public key (assuming it's in PEM format)
    block, _ := pem.Decode([]byte(tx.SenderPublicKey))
    if block == nil {
        return false
    }

    publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return false
    }

    publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
    if !ok {
        return false
    }

    // Assuming tx.Signature is a byte slice containing r and s concatenated
    r, s := new(big.Int).SetBytes(tx.Signature[:len(tx.Signature)/2]), new(big.Int).SetBytes(tx.Signature[len(tx.Signature)/2:])

    // Hash the transaction data
    txDataHash := sha256.Sum256([]byte(tx.String()))

    // Verify the signature with the public key
    valid := ecdsa.Verify(publicKey, txDataHash[:], r, s)
    return valid
}

// SecurePeerConnections manages and validates secure connections between network nodes
func (sm *SecurityMeasures) SecurePeerConnections() {
    // Setup a TLS config with strict security settings
    config := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519}, // Preferred curves which have hardware support
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        },
    }

    // Create a TLS listener to accept connections
    listener, err := tls.Listen("tcp", ":443", config)
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    defer listener.Close()

    log.Println("Secure peer connections established on port 443")
    for {
        // Accept connection
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }

        // Handle the connection in a new goroutine
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    // Process the connection
    log.Println("Connection from", conn.RemoteAddr())
}

