package network

import (
	"container/heap"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Constants for managing messaging
	MessageQueueSize     = 100
	MessageSendInterval  = 50 * time.Millisecond
	MessageRetryInterval = 500 * time.Millisecond
	MaxMessageRetries    = 5
	EncryptionAlgorithm  = "AES"

	// Constants for encryption
	ScryptN       = 1 << 15
	ScryptR       = 8
	ScryptP       = 1
	KeyLen        = 32
	SaltSize      = 16
	NonceSize     = 12

	// Constants for secure metadata exchange
	keySize        = 32
	nonceSize      = 12
	metadataMaxLen = 1024

	// Constants for multi-channel messaging
	tcp  = "tcp"
	udp  = "udp"
	ws   = "ws"
	tcpAddr = "localhost:8080"
	udpAddr = "localhost:8081"
	wsAddr  = "localhost:8082/ws"
)

// Push adds a message to the queue based on priority
func (mq *common.MessageQueue) Push(msg *common.Message) {
	mq.lock.Lock()
	defer mq.lock.Unlock()

	mq.messages = append(mq.messages, msg)
	mq.sort()
}

// Pop removes and returns the highest priority message from the queue
func (mq *common.MessageQueue) Pop() (*common.Message, error) {
	mq.lock.Lock()
	defer mq.lock.Unlock()

	if len(mq.messages) == 0 {
		return nil, errors.New("message queue is empty")
	}

	msg := mq.messages[0]
	mq.messages = mq.messages[1:]
	return msg, nil
}

// sort sorts the messages based on priority and timestamp
func (mq *common.MessageQueue) sort() {
	for i := 1; i < len(mq.messages); i++ {
		key := mq.messages[i]
		j := i - 1

		for j >= 0 && mq.messages[j].Priority < key.Priority {
			mq.messages[j+1] = mq.messages[j]
			j--
		}
		mq.messages[j+1] = key
	}
}


// AddMessage adds a new message to the priority queue
func (pqm *common.PriorityQueueManager) AddMessage(id string, payload []byte, priority int) {
	pqm.lock.Lock()
	defer pqm.lock.Unlock()

	message := &common.Message{
		ID:        id,
		Payload:   payload,
		Timestamp: time.Now(),
		Priority:  priority,
	}
	pqm.messageQueue.Push(message)
}

// GetMessage retrieves and removes the highest priority message from the queue
func (pqm *common.PriorityQueueManager) GetMessage() (*common.Message, error) {
	pqm.lock.Lock()
	defer pqm.lock.Unlock()

	if len(pqm.messageQueue.messages) == 0 {
		return nil, errors.New("message queue is empty")
	}

	message := pqm.messageQueue.Pop()
	return message, nil
}

// UpdateMessagePriority updates the priority of a message in the queue
func (pqm *common.PriorityQueueManager) UpdateMessagePriority(id string, newPriority int) error {
	pqm.lock.Lock()
	defer pqm.lock.Unlock()

	for _, message := range pqm.messageQueue.messages {
		if message.ID == id {
			message.Priority = newPriority
			pqm.messageQueue.sort()
			return nil
		}
	}
	return errors.New("message not found")
}

// AddNode adds a node to the P2P network
func (network *common.P2PNetwork) AddNode(node *common.Node) {
	network.lock.Lock()
	defer network.lock.Unlock()

	network.nodes[node.ID] = node
}

// RemoveNode removes a node from the P2P network
func (network *common.P2PNetwork) RemoveNode(nodeID string) {
	network.lock.Lock()
	defer network.lock.Unlock()

	delete(network.nodes, nodeID)
}

// SendMessage sends a message to a specific node
func (network *common.P2PNetwork) SendMessage(nodeID string, message *common.Message) error {
	network.lock.Lock()
	node, exists := network.nodes[nodeID]
	network.lock.Unlock()

	if !exists {
		return errors.New("node not found")
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", node.Address, node.Port))
	if err != nil {
		return err
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	return encoder.Encode(message)
}

// BroadcastMessage broadcasts a message to all nodes in the network
func (network *common.P2PNetwork) BroadcastMessage(message *common.Message) {
	network.lock.Lock()
	defer network.lock.Unlock()

	for _, node := range network.nodes {
		go func(n *Node) {
			err := network.SendMessage(n.ID, message)
			if err != nil {
				log.Printf("Failed to send message to node %s: %v", n.ID, err)
			}
		}(node)
	}
}

// ReceiveMessages listens for incoming messages on a specific port
func (network *common.P2PNetwork) ReceiveMessages(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", port, err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			var message Message
			decoder := json.NewDecoder(c)
			if err := decoder.Decode(&message); err != nil {
				log.Printf("Failed to decode message: %v", err)
				return
			}

			network.messageQueue.Push(&message)
		}(conn)
	}
}

// ProcessMessages continuously processes messages from the message queue
func (network *common.P2PNetwork) ProcessMessages() {
	for {
		message, err := network.messageQueue.Pop()
		if err != nil {
			time.Sleep(time.Second) // Wait before retrying if queue is empty
			continue
		}

		network.handleMessage(message)
	}
}

// handleMessage processes a single message
func (network *common.P2PNetwork) handleMessage(message *common.Message) {
	// Placeholder for actual message processing logic
	log.Printf("Processing message: %s with priority: %d", message.ID, message.Priority)
}

// EncryptMessage encrypts a message using a password and returns the encrypted message along with the salt used
func EncryptMessage(password string, message []byte) (string, string, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", err
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, NonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, message, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(salt), nil
}

// DecryptMessage decrypts an encrypted message using a password and salt
func DecryptMessage(password string, encryptedMessage string, salt string) ([]byte, error) {
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:NonceSize], ciphertext[NonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptMetadata encrypts the given metadata using AES-GCM
func (s *common.SecureMetadataExchange) EncryptMetadata(metadata *common.Metadata) (string, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}

	salt := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	aesKey, err := scrypt.Key(key, salt, 1<<15, 8, 1, keySize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, metadataJSON, nil)
	encryptedMetadata := append(salt, ciphertext...)

	return base64.StdEncoding.EncodeToString(encryptedMetadata), nil
}

// DecryptMetadata decrypts the given encrypted metadata using AES-GCM
func (s *common.SecureMetadataExchange) DecryptMetadata(encryptedMetadata string) (*common.Metadata, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedMetadata)
	if err != nil {
		return nil, err
	}

	salt := data[:keySize]
	ciphertext := data[keySize:]

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	aesKey, err := scrypt.Key(key, salt, 1<<15, 8, 1, keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var metadata Metadata
	if err := json.Unmarshal(plaintext, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// SignMetadata signs the metadata with the RSA private key
func (s *common.SecureMetadataExchange) SignMetadata(metadata *common.Metadata) error {
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%s%d%s%s%d", metadata.ID, metadata.Timestamp, metadata.Sender, metadata.Type, metadata.Priority)))

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	metadata.Signature = signature
	return nil
}

// VerifyMetadata verifies the metadata signature with the RSA public key
func (s *common.SecureMetadataExchange) VerifyMetadata(metadata *common.Metadata) error {
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%s%d%s%s%d", metadata.ID, metadata.Timestamp, metadata.Sender, metadata.Type, metadata.Priority)))

	err := rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, hashed[:], metadata.Signature)
	if err != nil {
		return err
	}

	return nil
}

// GenerateMetadata generates new metadata with a unique ID and timestamp
func GenerateMetadata(sender, msgType string, priority int) *common.Metadata {
	return &Metadata{
		ID:        uuid.New().String(),
		Timestamp: time.Now().Unix(),
		Sender:    sender,
		Type:      msgType,
		Priority:  priority,
	}
}



// AddConnection adds a new connection to the messenger
func (m *common.MultiChannelMessenger) AddConnection(conn *common.Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connections[conn.ID] = conn
}

// RemoveConnection removes a connection from the messenger
func (m *common.MultiChannelMessenger) RemoveConnection(connID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connections, connID)
}

// SendMessage sends a message over the specified connection
func (m *common.MultiChannelMessenger) SendMessage(connID string, message *common.Message) error {
	m.mu.Lock()
	conn, exists := m.connections[connID]
	m.mu.Unlock()

	if !exists {
		return errors.New("connection not found")
	}

	encryptedMessage, err := EncryptMessage("secret", message.Payload)
	if err != nil {
		return err
	}

	switch conn.ChannelType {
	case tcp:
		_, err = conn.TCPConn.Write([]byte(encryptedMessage))
	case udp:
		_, err = conn.UDPConn.Write([]byte(encryptedMessage))
	case ws:
		err = conn.WSConn.WriteMessage(websocket.BinaryMessage, []byte(encryptedMessage))
	default:
		err = errors.New("unsupported channel type")
	}

	return err
}

// ReceiveMessage receives a message from the specified connection
func (m *common.MultiChannelMessenger) ReceiveMessage(connID string) (Message *common.Message, error) {
	m.mu.Lock()
	conn, exists := m.connections[connID]
	m.mu.Unlock()

	if !exists {
		return nil, errors.New("connection not found")
	}

	var encryptedMessage []byte
	var err error

	switch conn.ChannelType {
	case tcp:
		encryptedMessage, err = readTCPMessage(conn.TCPConn)
	case udp:
		encryptedMessage, err = readUDPMessage(conn.UDPConn)
	case ws:
		_, encryptedMessage, err = conn.WSConn.ReadMessage()
	default:
		err = errors.New("unsupported channel type")
	}

	if err != nil {
		return nil, err
	}

	decryptedMessage, err := DecryptMessage("secret", string(encryptedMessage), "")
	if err != nil {
		return nil, err
	}

	message := &Message{}
	err = json.Unmarshal(decryptedMessage, message)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// readTCPMessage reads a message from a TCP connection
func readTCPMessage(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// readUDPMessage reads a message from a UDP connection
func readUDPMessage(conn *net.UDPConn) ([]byte, error) {
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// SetupConnections initializes TCP, UDP, and WebSocket connections
func (m *common.MultiChannelMessenger) SetupConnections() error {
	// Setup TCP connection
	tcpConn, err := net.Dial(tcp, tcpAddr)
	if err != nil {
		return err
	}
	m.AddConnection(&Connection{ID: "tcp1", TCPConn: tcpConn, ChannelType: tcp})

	// Setup UDP connection
	udpAddr, err := net.ResolveUDPAddr(udp, udpAddr)
	if err != nil {
		return err
	}
	udpConn, err := net.DialUDP(udp, nil, udpAddr)
	if err != nil {
		return err
	}
	m.AddConnection(&Connection{ID: "udp1", UDPConn: udpConn, ChannelType: udp})

	// Setup WebSocket connection
	wsConn, _, err := websocket.DefaultDialer.Dial(wsAddr, nil)
	if err != nil {
		return err
	}
	m.AddConnection(&Connection{ID: "ws1", WSConn: wsConn, ChannelType: ws})

	return nil
}


// NewContentBasedRoutingService creates a new instance of ContentBasedRoutingService
func NewContentBasedRoutingService(localNode *common.Node, discoveryService *common.DiscoveryService, protocolService *common.ProtocolService) (ContentBasedRoutingService *common.ContentBasedRoutingService) {
	return &ContentBasedRoutingService{
		localNode:    localNode,
		messageQueue: make(chan *common.Message, MessageQueueSize),
		statusMap:    make(map[string]*MessageStatus),
		discovery:    discoveryService,
		protocol:     protocolService,
	}
}

// Start begins the content-based routing service
func (cbrs *common.ContentBasedRoutingService) Start() {
	go cbrs.processMessageQueue()
	go cbrs.receiveMessages()
}

// processMessageQueue processes messages in the queue and routes them based on content
func (cbrs *common.ContentBasedRoutingService) processMessageQueue() {
	for {
		select {
		case message := <-cbrs.messageQueue:
			go cbrs.routeMessage(message)
			time.Sleep(MessageSendInterval)
		}
	}
}

// routeMessage routes a message to appropriate peers based on its content
func (cbrs *common.ContentBasedRoutingService) routeMessage(message *common.Message) {
	peers, err := cbrs.getRoutingPeers(message.Metadata)
	if err != nil {
		log.Printf("Failed to get routing peers: %v", err)
		return
	}

	for _, peer := range peers {
		cbrs.sendMessageToPeer(message, peer)
	}
}

// getRoutingPeers determines the peers to which a message should be routed based on its metadata
func (cbrs *common.ContentBasedRoutingService) getRoutingPeers(metadata map[string]string) ([]*common.Node, error) {
	var peers []*common.Node

	// Example: route based on "type" field in metadata
	if msgType, exists := metadata["type"]; exists {
		peerIDs := cbrs.discovery.FindPeersByType(msgType)
		for _, peerID := range peerIDs {
			peer, err := cbrs.discovery.GetPeer(peerID)
			if err == nil {
				peers = append(peers, peer)
			}
		}
	}

	if len(peers) == 0 {
		return nil, errors.New("no suitable peers found for routing")
	}
	return peers, nil
}

// sendMessageToPeer sends a message to a specified peer
func (cbrs *common.ContentBasedRoutingService) sendMessageToPeer(message *common.Message, peer *common.Node) {
	encryptedMessage, err := EncryptMessage(peer.PublicKey, message.Payload)
	if err != nil {
		log.Printf("Failed to encrypt message: %v", err)
		return
	}

	err = cbrs.protocol.Send(peer.Address, encryptedMessage)
	if err != nil {
		cbrs.handleFailedMessage(message)
	} else {
		cbrs.updateMessageStatus(message.ID, "sent")
	}
}

// handleFailedMessage handles messages that failed to send
func (cbrs *common.ContentBasedRoutingService) handleFailedMessage(message *common.Message) {
	cbrs.lock.Lock()
	defer cbrs.lock.Unlock()

	status, exists := cbrs.statusMap[message.ID]
	if !exists {
		status = &MessageStatus{
			ID:      message.ID,
			Status:  "retrying",
			Retries: 0,
		}
		cbrs.statusMap[message.ID] = status
	}

	if status.Retries < MaxMessageRetries {
		status.Retries++
		time.AfterFunc(MessageRetryInterval, func() {
			cbrs.messageQueue <- message
		})
	} else {
		status.Status = "failed"
		log.Printf("Message %s failed after %d retries", message.ID, MaxMessageRetries)
	}
}

// updateMessageStatus updates the status of a message
func (cbrs *common.ContentBasedRoutingService) updateMessageStatus(messageID, status string) {
	cbrs.lock.Lock()
	defer cbrs.lock.Unlock()

	messageStatus, exists := cbrs.statusMap[messageID]
	if !exists {
		messageStatus = &MessageStatus{
			ID:      messageID,
			Status:  status,
			Retries: 0,
		}
		cbrs.statusMap[messageID] = messageStatus
	} else {
		messageStatus.Status = status
	}
}

// SendMessage adds a message to the queue for routing
func (cbrs *common.ContentBasedRoutingService) SendMessage(receiverID string, payload []byte, metadata map[string]string) (string, error) {
	messageID := HashMessage(payload)
	message := &common.Message{
		ID:       messageID,
		Payload:  payload,
		Sender:   receiverID,
		Metadata: metadata,
	}

	cbrs.messageQueue <- message
	return messageID, nil
}

// receiveMessages handles incoming messages
func (cbrs *common.ContentBasedRoutingService) receiveMessages() {
	for {
		msg, addr, err := cbrs.protocol.Receive()
		if err != nil {
			log.Printf("Failed to receive message: %v", err)
			continue
		}

		peerID := HashMessage(addr)
		peer, err := cbrs.discovery.GetPeer(peerID)
		if err != nil {
			log.Printf("Unknown peer: %v", err)
			continue
		}

		decryptedMessage, err := DecryptMessage(peer.PublicKey, string(msg), "")
		if err != nil {
			log.Printf("Failed to decrypt message: %v", err)
			continue
		}

		cbrs.processReceivedMessage(decryptedMessage)
	}
}

// processReceivedMessage processes an incoming message
func (cbrs *common.ContentBasedRoutingService) processReceivedMessage(message []byte) {
	var msg common.Message
	err := json.Unmarshal(message, &msg)
	if err != nil {
		log.Printf("Failed to unmarshal message: %v", err)
		return
	}

	log.Printf("Received message: %s", msg.Payload)
	// Implement further message processing logic here
}



// Start begins the asynchronous messaging service
func (ams *AsynchronousMessagingService) Start() {
	go ams.processMessageQueue()
	go ams.receiveMessages()
}

// processMessageQueue processes messages in the queue asynchronously
func (ams *AsynchronousMessagingService) ProcessMessageQueue() {
	for {
		select {
		case message := <-ams.messageQueue:
			go ams.sendMessageToNetwork(message)
			time.Sleep(MessageSendInterval)
		}
	}
}

// sendMessageToNetwork sends a message to the network
func (ams *common.AsynchronousMessagingService) sendMessageToNetwork(message *common.Message) {
	peer, err := ams.discovery.FindPeer(message.Sender)
	if err != nil {
		log.Printf("Failed to find peer: %v", err)
		return
	}

	encryptedMessage, err := EncryptMessage(peer.PublicKey, message.Payload)
	if err != nil {
		log.Printf("Failed to encrypt message: %v", err)
		return
	}

	err = ams.protocol.Send(peer.Address, encryptedMessage)
	if err != nil {
		ams.handleFailedMessage(message)
	} else {
		ams.updateMessageStatus(message.ID, "sent")
	}
}

// handleFailedMessage handles messages that failed to send
func (ams *common.AsynchronousMessagingService) handleFailedMessage(message *common.Message) {
	ams.lock.Lock()
	defer ams.lock.Unlock()

	status, exists := ams.statusMap[message.ID]
	if !exists {
		status = &common.MessageStatus{
			ID:      message.ID,
			Status:  "retrying",
			Retries: 0,
		}
		ams.statusMap[message.ID] = status
	}

	if status.Retries < MaxMessageRetries {
		status.Retries++
		time.AfterFunc(MessageRetryInterval, func() {
			ams.messageQueue <- message
		})
	} else {
		status.Status = "failed"
		log.Printf("Message %s failed after %d retries", message.ID, MaxMessageRetries)
	}
}

// updateMessageStatus updates the status of a message
func (ams *common.AsynchronousMessagingService) updateMessageStatus(messageID, status string) {
	ams.lock.Lock()
	defer ams.lock.Unlock()

	messageStatus, exists := ams.statusMap[messageID]
	if !exists {
		messageStatus = &common.MessageStatus{
			ID:      messageID,
			Status:  status,
			Retries: 0,
		}
		ams.statusMap[messageID] = messageStatus
	} else {
		messageStatus.Status = status
	}
}

// SendMessage adds a message to the queue for sending
func (ams *common.AsynchronousMessagingService) SendMessage(receiverID string, payload []byte) (string, error) {
	messageID := HashMessage(payload)
	message := &common.Message{
		ID:      messageID,
		Payload:  payload,
		Sender:   receiverID,
	}

	ams.messageQueue <- message
	return messageID, nil
}

// receiveMessages handles incoming messages
func (ams *common.AsynchronousMessagingService) receiveMessages() {
	for {
		msg, addr, err := ams.protocol.Receive()
		if err != nil {
			log.Printf("Failed to receive message: %v", err)
			continue
		}

		peerID := HashMessage(addr)
		peer, err := ams.discovery.FindPeer(peerID)
		if err != nil {
			log.Printf("Unknown peer: %v", err)
			continue
		}

		decryptedMessage, err := DecryptMessage(peer.PublicKey, string(msg), "")
		if err != nil {
			log.Printf("Failed to decrypt message: %v", err)
			continue
		}

		ams.processReceivedMessage(decryptedMessage)
	}
}

// processReceivedMessage processes an incoming message
func (ams *common.AsynchronousMessagingService) processReceivedMessage(message []byte) {
	var msg common.Message
	err := json.Unmarshal(message, &msg)
	if err != nil {
		log.Printf("Failed to unmarshal message: %v", err)
		return
	}

	log.Printf("Received message: %s", msg.Payload)
	// Implement further message processing logic here
}

// HashMessage hashes a message using SHA-256
func HashMessage(message []byte) string {
	hash := sha256.Sum256(message)
	return base64.StdEncoding.EncodeToString(hash[:])
}

