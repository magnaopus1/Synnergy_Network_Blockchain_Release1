package main

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

    "github.com/syndtr/goleveldb/leveldb"
    "golang.org/x/crypto/scrypt"
)

// HybridNode represents a hybrid node in the Synthron blockchain.
type HybridNode struct {
    ID              string
    Address         string
    Db              *leveldb.DB
    Connections     map[string]net.Conn
    ConnMutex       sync.Mutex
    BlockProposals  chan Block
    TransactionPool chan Transaction
    StopChan        chan struct{}
}

// Block represents a block in the blockchain.
type Block struct {
    Index        int
    PreviousHash string
    Timestamp    int64
    Data         string
    Hash         string
}

// Transaction represents a transaction in the blockchain.
type Transaction struct {
    ID     string
    Amount int
    From   string
    To     string
}

// NewHybridNode initializes and returns a new HybridNode.
func NewHybridNode(id, address string) (*HybridNode, error) {
    db, err := leveldb.OpenFile(fmt.Sprintf("db/%s", id), nil)
    if err != nil {
        return nil, err
    }

    return &HybridNode{
        ID:              id,
        Address:         address,
        Db:              db,
        Connections:     make(map[string]net.Conn),
        BlockProposals:  make(chan Block),
        TransactionPool: make(chan Transaction),
        StopChan:        make(chan struct{}),
    }, nil
}

// Start initiates the hybrid node operations.
func (node *HybridNode) Start() {
    go node.listen()
    go node.handleBlockProposals()
    go node.handleTransactions()
    log.Printf("HybridNode %s started at %s", node.ID, node.Address)
}

// Stop gracefully shuts down the hybrid node.
func (node *HybridNode) Stop() {
    close(node.StopChan)
    node.Db.Close()
    for _, conn := range node.Connections {
        conn.Close()
    }
    log.Printf("HybridNode %s stopped", node.ID)
}

func (node *HybridNode) listen() {
    listener, err := net.Listen("tcp", node.Address)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    for {
        select {
        case <-node.StopChan:
            return
        default:
            conn, err := listener.Accept()
            if err != nil {
                log.Println(err)
                continue
            }
            node.ConnMutex.Lock()
            node.Connections[conn.RemoteAddr().String()] = conn
            node.ConnMutex.Unlock()
            go node.handleConnection(conn)
        }
    }
}

func (node *HybridNode) handleConnection(conn net.Conn) {
    defer func() {
        conn.Close()
        node.ConnMutex.Lock()
        delete(node.Connections, conn.RemoteAddr().String())
        node.ConnMutex.Unlock()
    }()

    // Handle connection logic here (e.g., reading data, responding to requests)
}

func (node *HybridNode) handleBlockProposals() {
    for {
        select {
        case block := <-node.BlockProposals:
            // Handle block proposals (e.g., validate and add to blockchain)
        case <-node.StopChan:
            return
        }
    }
}

func (node *HybridNode) handleTransactions() {
    for {
        select {
        case tx := <-node.TransactionPool:
            // Handle transactions (e.g., validate and add to transaction pool)
        case <-node.StopChan:
            return
        }
    }
}

// Encrypt encrypts data using AES encryption.
func Encrypt(data, passphrase string) (string, error) {
    salt := make([]byte, 8)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(data))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))

    return fmt.Sprintf("%x", salt) + fmt.Sprintf("%x", ciphertext), nil
}

// Decrypt decrypts data using AES decryption.
func Decrypt(encrypted, passphrase string) (string, error) {
    salt, err := hex.DecodeString(encrypted[:16])
    if err != nil {
        return "", err
    }

    ciphertext, err := hex.DecodeString(encrypted[16:])
    if err != nil {
        return "", err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return string(ciphertext), nil
}

func main() {
    node, err := NewHybridNode("node1", "localhost:8080")
    if err != nil {
        log.Fatalf("Failed to create node: %v", err)
    }
    node.Start()

    // Wait for a signal to stop
    stopChan := make(chan os.Signal, 1)
    <-stopChan
    node.Stop()
}
