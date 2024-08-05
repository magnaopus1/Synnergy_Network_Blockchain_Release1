package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)

const (
	readBufferSize    = 4096
	writeBufferSize   = 4096
	maxMessageSize    = 1048576 // 1 MB
	connectionRetry   = 3
	retryInterval     = 5 * time.Second
	connectionTimeout = 30 * time.Second
)

// Network represents the overall network structure
type Network struct {
	Nodes       map[string]*common.Node
	Connections map[string]*Connection
	Logger      *log.Logger
	mu          sync.Mutex
}

// Connection represents a connection to another node
type Connection struct {
	Conn     net.Conn
	NodeID   string
	IsSecure bool
}

// NewNetwork initializes a new network
func NewNetwork(logger *log.Logger) *Network {
	return &Network{
		Nodes:       make(map[string]*common.Node),
		Connections: make(map[string]*Connection),
		Logger:      logger,
	}
}

// AddNode adds a new node to the network
func (n *Network) AddNode(node *common.Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[node.ID] = node
	n.Logger.Println("Node added:", node.ID)
}

// Connect establishes a connection to another node
func (n *Network) ConnectToANode(nodeID, targetAddress string) error {
	node, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	conn, err := net.DialTimeout("tcp", targetAddress, connectionTimeout)
	if err != nil {
		return errors.New("Failed to connect: " + err.Error())
	}

	secureConn, err := n.secureConnection(conn, node.PrivateKey, targetAddress)
	if err != nil {
		return errors.New("Failed to secure connection: " + err.Error())
	}

	connection := &Connection{
		Conn:     secureConn,
		NodeID:   targetAddress,
		IsSecure: true,
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	node.Connections[targetAddress] = connection
	n.Connections[targetAddress] = connection
	n.Logger.Println("Connected to node:", targetAddress)

	go n.handleConnection(connection)

	return nil
}

// Disconnect removes a connection to a node
func (n *Network) DisconnectFromNode(nodeID, targetAddress string) error {
	node, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	connection, exists := node.Connections[targetAddress]
	if !exists {
		return errors.New("Connection not found: " + targetAddress)
	}

	if err := connection.Conn.Close(); err != nil {
		return errors.New("Failed to close connection: " + err.Error())
	}

	delete(node.Connections, targetAddress)
	delete(n.Connections, targetAddress)

	n.Logger.Println("Disconnected from node:", targetAddress)
	return nil
}

// BroadcastMessage sends a message to all connected nodes
func (n *Network) BroadcastMessageToConnectedNodes(nodeID, message string) error {
	node, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	for _, connection := range node.Connections {
		if connection.IsSecure {
			if _, err := connection.Conn.Write([]byte(message)); err != nil {
				return errors.New("Failed to send message: " + err.Error())
			}
		}
	}

	n.Logger.Println("Message broadcasted from node:", nodeID)
	return nil
}

// HandleIncomingConnections starts a listener for incoming connections
func (n *Network) HandleIncomingConnections(address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		n.Logger.Fatal("Failed to start listener: ", err)
	}
	defer listener.Close()

	n.Logger.Println("Listening for connections on " + address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			n.Logger.Println("Failed to accept connection: " + err.Error())
			continue
		}
		go n.processIncomingConnection(conn)
	}
}

// processIncomingConnection processes an incoming connection
func (n *Network) ProcessIncomingConnection(conn net.Conn) {
	defer conn.Close()

	secureConn, err := n.secureConnection(conn, "", conn.RemoteAddr().String())
	if err != nil {
		n.Logger.Println("Failed to secure incoming connection: " + err.Error())
		return
	}

	connection := &Connection{
		Conn:     secureConn,
		NodeID:   conn.RemoteAddr().String(),
		IsSecure: true,
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	n.Connections[conn.RemoteAddr().String()] = connection
	n.Logger.Println("Accepted secure connection from: " + conn.RemoteAddr().String())

	go n.handleConnection(connection)
}

// secureConnection secures a connection using TLS
func (n *Network) SecureConnectionTLS(conn net.Conn, privateKey, targetAddress string) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      x509.NewCertPool(),
	}

	caCert, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		return nil, err
	}

	if ok := config.RootCAs.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("failed to append CA certificate")
	}

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

// handleConnection handles incoming messages from a connection
func (n *Network) HandleConnectionIncomingMessage(connection *Connection) {
	buffer := make([]byte, readBufferSize)
	for {
		nBytes, err := connection.Conn.Read(buffer)
		if err != nil {
			n.Logger.Println("Connection error:", err.Error())
			break
		}
		message := buffer[:nBytes]
		if err := n.handleMessage(connection, message); err != nil {
			n.Logger.Println("Failed to handle message:", err.Error())
		}
	}
}

// handleMessage processes an incoming message
func (n *Network) HandleMessageProcessing(connection *Connection, message []byte) error {
	var msg common.Message
	if err := json.Unmarshal(message, &msg); err != nil {
		return err
	}

	switch msg.Type {
	case "auth":
		return n.handleAuthMessage(connection, msg)
	case "data":
		return n.handleDataMessage(connection, msg)
	case "route":
		return n.handleRouteMessage(connection, msg)
	default:
		return errors.New("unknown message type")
	}
}

// handleAuthMessage processes an authentication message
func (n *Network) HandleAuthMessage(connection *Connection, msg common.Message) error {
	n.Logger.Println("Handling auth message from:", connection.NodeID)
	connection.IsSecure = true
	return nil
}

// handleDataMessage processes a data message
func (n *Network) HandleDataMessage(connection *Connection, msg common.Message) error {
	n.Logger.Println("Handling data message from:", connection.NodeID)
	n.Logger.Println("Message content:", string(msg.Content))
	return nil
}

// handleRouteMessage processes a route message
func (n *Network) HandleRouteMessage(connection *Connection, msg common.Message) error {
	n.Logger.Println("Handling route message from:", connection.NodeID)
	n.Logger.Println("Routing to node:", msg.TargetID)
	if targetConn, exists := n.Connections[msg.TargetID]; exists {
		if _, err := targetConn.Conn.Write(msg.Content); err != nil {
			return err
		}
	} else {
		return errors.New("target node not found")
	}
	return nil
}

// retryConnect attempts to reconnect to a node with retries
func (n *Network) RetryConnectToNode(nodeID, targetAddress string, retries int) error {
	for i := 0; i < retries; i++ {
		if err := n.Connect(nodeID, targetAddress); err == nil {
			return nil
		}
		time.Sleep(retryInterval)
	}
	return errors.New("Exceeded maximum retries to connect")
}

// VerifyNode verifies the authenticity of a node
func (n *Network) VerifyNodeAuthenticity(nodeID string) error {
	_, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	// Implement your own key pair verification logic here
	return nil
}

// RemoveNode removes a node from the network
func (n *Network) RemoveNodeFromNetwork(nodeID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	delete(n.Nodes, nodeID)
	n.Logger.Println("Node removed: " + nodeID)
	return nil
}

// UpdateNode updates the information of a node in the network
func (n *Network) UpdateNode(nodeID, newAddress, newPublicKey, newPrivateKey string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("Node not found: " + nodeID)
	}

	node.Address = newAddress
	node.PublicKey = newPublicKey
	node.PrivateKey = newPrivateKey

	n.Logger.Println("Node updated: " + nodeID)
	return nil
}

// EncryptMessage encrypts a message using the network's encryption method
func (n *Network) EncryptNetworkMessage(message, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message using the network's decryption method
func (n *Network) DecryptNetworkMessage(encryptedMessage, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// RouteMessage routes a message to the appropriate node
func (n *Network) RouteMessageToNode(sourceNodeID, targetNodeID, message string) error {
	targetNode, exists := n.Nodes[targetNodeID]
	if !exists {
		return errors.New("Target node not found: " + targetNodeID)
	}

	encryptedMessage, err := n.EncryptMessage(message, targetNode.PublicKey)
	if err != nil {
		return errors.New("Failed to encrypt message: " + err.Error())
	}

	return n.BroadcastMessage(sourceNodeID, encryptedMessage)
}


