package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "math/big"
    "net"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
)

// LightningNode represents a node in the Lightning Network for the Synthron blockchain.
type LightningNode struct {
    ID            string
    PublicKey     string
    PrivateKey    string
    Channels      map[string]*PaymentChannel
    ChannelMutex  sync.Mutex
    ListenAddress string
    conn          net.Listener
    quit          chan struct{}
}

// PaymentChannel represents a payment channel between two nodes.
type PaymentChannel struct {
    ChannelID   string
    Node1       string
    Node2       string
    Balance1    *big.Int
    Balance2    *big.Int
    ChannelKey  []byte
    ChannelOpen bool
}

// NewLightningNode initializes and returns a new LightningNode.
func NewLightningNode(id, publicKey, privateKey, listenAddress string) *LightningNode {
    return &LightningNode{
        ID:            id,
        PublicKey:     publicKey,
        PrivateKey:    privateKey,
        Channels:      make(map[string]*PaymentChannel),
        ListenAddress: listenAddress,
        quit:          make(chan struct{}),
    }
}

// Start initializes the network listener for the LightningNode.
func (ln *LightningNode) Start() error {
    ln.ChannelMutex.Lock()
    defer ln.ChannelMutex.Unlock()

    var err error
    ln.conn, err = net.Listen("tcp", ln.ListenAddress)
    if err != nil {
        return err
    }
    log.Printf("LightningNode %s listening on %s", ln.ID, ln.ListenAddress)
    
    go ln.acceptConnections()
    return nil
}

// Stop gracefully shuts down the LightningNode.
func (ln *LightningNode) Stop() {
    close(ln.quit)
    ln.conn.Close()
    log.Printf("LightningNode %s stopped", ln.ID)
}

// acceptConnections handles incoming network connections.
func (ln *LightningNode) acceptConnections() {
    for {
        select {
        case <-ln.quit:
            return
        default:
            conn, err := ln.conn.Accept()
            if err != nil {
                log.Println("Error accepting connection:", err)
                continue
            }
            go ln.handleConnection(conn)
        }
    }
}

// handleConnection processes an incoming connection.
func (ln *LightningNode) handleConnection(conn net.Conn) {
    defer conn.Close()
    // Handle the connection
}

// OpenChannel creates a new payment channel between the LightningNode and another node.
func (ln *LightningNode) OpenChannel(nodeID string, initialBalance *big.Int) (*PaymentChannel, error) {
    ln.ChannelMutex.Lock()
    defer ln.ChannelMutex.Unlock()

    channelID := generateChannelID(ln.ID, nodeID)
    key := generateChannelKey(ln.ID, nodeID)

    channel := &PaymentChannel{
        ChannelID:   channelID,
        Node1:       ln.ID,
        Node2:       nodeID,
        Balance1:    initialBalance,
        Balance2:    big.NewInt(0),
        ChannelKey:  key,
        ChannelOpen: true,
    }
    ln.Channels[channelID] = channel
    return channel, nil
}

// CloseChannel closes an existing payment channel.
func (ln *LightningNode) CloseChannel(channelID string) error {
    ln.ChannelMutex.Lock()
    defer ln.ChannelMutex.Unlock()

    channel, exists := ln.Channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    channel.ChannelOpen = false
    delete(ln.Channels, channelID)
    return nil
}

// SendPayment sends a payment through an existing payment channel.
func (ln *LightningNode) SendPayment(channelID string, amount *big.Int) error {
    ln.ChannelMutex.Lock()
    defer ln.ChannelMutex.Unlock()

    channel, exists := ln.Channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    if !channel.ChannelOpen {
        return errors.New("channel is closed")
    }
    if channel.Node1 == ln.ID {
        if channel.Balance1.Cmp(amount) < 0 {
            return errors.New("insufficient balance")
        }
        channel.Balance1.Sub(channel.Balance1, amount)
        channel.Balance2.Add(channel.Balance2, amount)
    } else {
        if channel.Balance2.Cmp(amount) < 0 {
            return errors.New("insufficient balance")
        }
        channel.Balance2.Sub(channel.Balance2, amount)
        channel.Balance1.Add(channel.Balance1, amount)
    }
    return nil
}

// generateChannelID generates a unique channel ID based on the node IDs.
func generateChannelID(node1, node2 string) string {
    return fmt.Sprintf("%s-%s-%d", node1, node2, time.Now().UnixNano())
}

// generateChannelKey generates a cryptographic key for the payment channel.
func generateChannelKey(node1, node2 string) []byte {
    salt := []byte(node1 + node2)
    key, _ := scrypt.Key([]byte(node1+node2), salt, 16384, 8, 1, 32)
    return key
}

// Encrypt encrypts data using AES encryption.
func Encrypt(data, passphrase []byte) (string, error) {
    block, _ := aes.NewCipher(passphrase)
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES encryption.
func Decrypt(data string, passphrase []byte) ([]byte, error) {
    block, err := aes.NewCipher(passphrase)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    ciphertext, _ := hex.DecodeString(data)
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// hashPassword hashes a password using SHA-256.
func hashPassword(password string) string {
    hash := sha256.New()
    hash.Write([]byte(password))
    return hex.EncodeToString(hash.Sum(nil))
}

func main() {
    // Example usage of the LightningNode
    node := NewLightningNode("node1", "publicKey1", "privateKey1", ":8080")
    err := node.Start()
    if err != nil {
        log.Fatalf("Failed to start LightningNode: %v", err)
    }
    defer node.Stop()

    // Open a payment channel
    initialBalance := big.NewInt(1000)
    channel, err := node.OpenChannel("node2", initialBalance)
    if err != nil {
        log.Fatalf("Failed to open payment channel: %v", err)
    }
    fmt.Printf("Opened channel: %v\n", channel)

    // Send a payment
    err = node.SendPayment(channel.ChannelID, big.NewInt(100))
    if err != nil {
        log.Fatalf("Failed to send payment: %v", err)
    }
    fmt.Printf("Sent payment through channel: %v\n", channel)
}
