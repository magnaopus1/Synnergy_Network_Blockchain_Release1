package supernode

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "sync"
    "time"
    "github.com/synthron_blockchain_final/pkg/layer0/node/super_node/config"
    "github.com/synthron_blockchain_final/pkg/layer0/node/super_node/storage"
    "github.com/synthron_blockchain_final/pkg/layer0/node/super_node/transaction"
    "github.com/synthron_blockchain_final/pkg/layer0/node/super_node/smartcontract"
    "github.com/synthron_blockchain_final/pkg/layer0/node/super_node/privacy"
)

// SuperNode represents a Super Node in the Synthron blockchain.
type SuperNode struct {
    Config     *config.Config
    Storage    *storage.Storage
    Network    *net.Listener
    Transactions chan transaction.Transaction
    SmartContracts chan smartcontract.SmartContract
    Privacy   *privacy.Privacy
    Quit      chan bool
    wg        sync.WaitGroup
}

// NewSuperNode initializes a new SuperNode with the provided configuration.
func NewSuperNode(cfg *config.Config) (*SuperNode, error) {
    // Initialize storage
    storage, err := storage.NewStorage(cfg.StoragePath)
    if err != nil {
        return nil, err
    }

    // Initialize network listener
    listener, err := net.Listen("tcp", cfg.NetworkAddress)
    if err != nil {
        return nil, err
    }

    // Initialize privacy
    privacy, err := privacy.NewPrivacy(cfg.PrivacyConfig)
    if err != nil {
        return nil, err
    }

    node := &SuperNode{
        Config:        cfg,
        Storage:       storage,
        Network:       &listener,
        Transactions:  make(chan transaction.Transaction, cfg.TransactionBufferSize),
        SmartContracts: make(chan smartcontract.SmartContract, cfg.SmartContractBufferSize),
        Privacy:       privacy,
        Quit:          make(chan bool),
    }

    return node, nil
}

// Start begins the operation of the SuperNode.
func (n *SuperNode) Start() {
    log.Println("Starting SuperNode...")
    n.wg.Add(1)
    go n.handleConnections()

    n.wg.Add(1)
    go n.processTransactions()

    n.wg.Add(1)
    go n.executeSmartContracts()

    n.wg.Wait()
}

// Stop gracefully stops the SuperNode.
func (n *SuperNode) Stop() {
    log.Println("Stopping SuperNode...")
    close(n.Quit)
    (*n.Network).Close()
    n.wg.Wait()
}

// handleConnections handles incoming network connections.
func (n *SuperNode) handleConnections() {
    defer n.wg.Done()
    for {
        conn, err := (*n.Network).Accept()
        if err != nil {
            select {
            case <-n.Quit:
                return
            default:
                log.Printf("Failed to accept connection: %v", err)
                continue
            }
        }
        n.wg.Add(1)
        go n.handleConnection(conn)
    }
}

// handleConnection processes an individual network connection.
func (n *SuperNode) handleConnection(conn net.Conn) {
    defer conn.Close()
    defer n.wg.Done()

    buf := make([]byte, 4096)
    for {
        select {
        case <-n.Quit:
            return
        default:
            n, err := conn.Read(buf)
            if err != nil {
                if err != io.EOF {
                    log.Printf("Failed to read from connection: %v", err)
                }
                return
            }

            // Decrypt data
            data, err := n.decryptData(buf[:n])
            if err != nil {
                log.Printf("Failed to decrypt data: %v", err)
                return
            }

            // Process transaction or smart contract
            go n.processData(data)
        }
    }
}

// processData processes the incoming data and routes it accordingly.
func (n *SuperNode) processData(data []byte) {
    // Determine if the data is a transaction or smart contract and route it accordingly
    if transaction.IsTransaction(data) {
        tx, err := transaction.NewTransaction(data)
        if err != nil {
            log.Printf("Invalid transaction: %v", err)
            return
        }
        n.Transactions <- tx
    } else if smartcontract.IsSmartContract(data) {
        sc, err := smartcontract.NewSmartContract(data)
        if err != nil {
            log.Printf("Invalid smart contract: %v", err)
            return
        }
        n.SmartContracts <- sc
    } else {
        log.Printf("Unknown data type")
    }
}

// processTransactions processes incoming transactions.
func (n *SuperNode) processTransactions() {
    defer n.wg.Done()
    for {
        select {
        case tx := <-n.Transactions:
            // Validate and store the transaction
            if err := tx.Validate(); err != nil {
                log.Printf("Invalid transaction: %v", err)
                continue
            }

            if err := n.Storage.StoreTransaction(tx); err != nil {
                log.Printf("Failed to store transaction: %v", err)
                continue
            }

            log.Printf("Processed transaction: %v", tx.ID)

        case <-n.Quit:
            return
        }
    }
}

// executeSmartContracts executes incoming smart contracts.
func (n *SuperNode) executeSmartContracts() {
    defer n.wg.Done()
    for {
        select {
        case sc := <-n.SmartContracts:
            // Execute the smart contract
            if err := sc.Execute(); err != nil {
                log.Printf("Failed to execute smart contract: %v", err)
                continue
            }

            if err := n.Storage.StoreSmartContract(sc); err != nil {
                log.Printf("Failed to store smart contract: %v", err)
                continue
            }

            log.Printf("Executed smart contract: %v", sc.ID)

        case <-n.Quit:
            return
        }
    }
}

// decryptData decrypts incoming data using the configured encryption method.
func (n *SuperNode) decryptData(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(n.Config.EncryptionKey)
    if err != nil {
        return nil, err
    }

    if len(data) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }

    iv := data[:aes.BlockSize]
    data = data[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(data, data)

    return data, nil
}

// encryptData encrypts outgoing data using the configured encryption method.
func (n *SuperNode) encryptData(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(n.Config.EncryptionKey)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

    return ciphertext, nil
}

// monitorHealth continuously monitors the health of the Super Node.
func (n *SuperNode) monitorHealth() {
    for {
        select {
        case <-time.After(n.Config.HealthCheckInterval):
            if err := n.checkHealth(); err != nil {
                log.Printf("Health check failed: %v", err)
            }
        case <-n.Quit:
            return
        }
    }
}

// checkHealth performs a health check on the Super Node.
func (n *SuperNode) checkHealth() error {
    // Implement health check logic (e.g., check disk space, memory usage, network connectivity)
    return nil
}

// main function to start the Super Node.
func main() {
    cfg, err := config.LoadConfig("config.toml")
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    node, err := NewSuperNode(cfg)
    if err != nil {
        log.Fatalf("Failed to create SuperNode: %v", err)
    }

    go node.monitorHealth()

    node.Start()
    defer node.Stop()
}
