package network

import (
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
	"math/big"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)


func (e *common.CustomError) Error() string {
	return fmt.Sprintf("[%d] %s: %s\nOccurred at: %s\nContext: %v\nStackTrace: %s",
		e.Code, e.Message, e.Timestamp.Format(time.RFC3339), e.ContextInfo, e.StackTrace)
}

func NewCustomError(code int, message string, contextInfo map[string]interface{}) *common.CustomError {
	return &CustomError{
		Code:        code,
		Message:     message,
		Timestamp:   time.Now(),
		StackTrace:  getStackTrace(),
		ContextInfo: contextInfo,
	}
}

func GetStackTrace() string {
	stackBuf := make([]byte, 1024)
	count := runtime.Stack(stackBuf, false)
	return string(stackBuf[:count])
}

func LogError(err common.error) {
	if customErr, ok := err.(*common.CustomError); ok {
		log.Printf("Error: %v\n", customErr.Error())
	} else {
		log.Printf("Error: %v\n", err)
	}
}

func HandleError(err common.error) {
	LogError(err)
	// Add custom handling logic based on error severity or type
	if customErr, ok := err.(*common.CustomError); ok {
		switch customErr.Code {
		case 100:
			// Handle specific error code 100
			// Example: Retry operation, send alert, etc.
		case 200:
			// Handle specific error code 200
			// Example: Clean up resources, initiate recovery, etc.
		default:
			// Handle general errors
		}
	}
}

type AdaptivePrioritization struct {
	mu           sync.Mutex
	messageQueue []*common.Message
	logger       *common.Logger
	qosManager   *QoSManager
	encManager   *common.EncryptionManager
	secManager   *common.SecurityManager
}

func NewAdaptivePrioritization(logger *common.Logger, qosManager *QoSManager, encManager *common.EncryptionManager, secManager *common.SecurityManager) *AdaptivePrioritization {
	return &AdaptivePrioritization{
		messageQueue: make([]*Message, 0),
		logger:       logger,
		qosManager:   qosManager,
		encManager:   encManager,
		secManager:   secManager,
	}
}

func (ap *AdaptivePrioritization) AddAdaptivePrioritization(msg *common.Message) common.error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	encryptedData, err := ap.encManager.Encrypt(msg.Data)
	if err != nil {
		ap.logger.Error("Failed to encrypt message data: ", err)
		return err
	}

	if err := ap.secManager.ValidateMessage(encryptedData); err != nil {
		ap.logger.Error("Message validation failed: ", err)
		return err
	}

	msg.Data = encryptedData
	ap.messageQueue = append(ap.messageQueue, msg)
	ap.logger.Info("Message added to queue: ", msg.ID)
	return nil
}

func (ap *AdaptivePrioritization) PrioritizeMessages() {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	sort.Slice(ap.messageQueue, func(i, j int) bool {
		if ap.messageQueue[i].Priority == ap.messageQueue[j].Priority {
			return ap.messageQueue[i].Timestamp.Before(ap.messageQueue[j].Timestamp)
		}
		return ap.messageQueue[i].Priority > ap.messageQueue[j].Priority
	})

	ap.logger.Info("Message queue prioritized")
}

func (ap *AdaptivePrioritization) ProcessMessages() {
	for {
		ap.mu.Lock()
		if len(ap.messageQueue) == 0 {
			ap.mu.Unlock()
			time.Sleep(1 * time.Second)
			continue
		}

		msg := ap.messageQueue[0]
		ap.messageQueue = ap.messageQueue[1:]
		ap.mu.Unlock()

		decryptedData, err := ap.encManager.Decrypt(msg.Data)
		if err != nil {
			ap.logger.Error("Failed to decrypt message data: ", err)
			continue
		}

		if err := ap.qosManager.EnforceQoS(decryptedData); err != nil {
			ap.logger.Error("QoS enforcement failed: ", err)
			continue
		}

		ap.handleMessage(decryptedData)
		ap.logger.Info("Message processed: ", msg.ID)
	}
}

func (ap *AdaptivePrioritization) HandleMessage(data []byte) {
	ap.logger.Info("Handling message data: ", string(data))
}

type MessageReception struct {
	listenAddr   string
	logger       *common.Logger
	conn         net.Listener
	mutex        sync.Mutex
	messageQueue chan Message
}

func NewMessageReception(listenAddr string, logger *common.Logger) (*MessageReception, common.error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to start listener: %w", err)
	}

	return &MessageReception{
		listenAddr:   listenAddr,
		logger:       logger,
		conn:         listener,
		messageQueue: make(chan Message, 100),
	}, nil
}

func (mr *MessageReception) StartServer() {
	defer mr.conn.Close()
	mr.logger.Info("Message reception server started on", mr.listenAddr)

	for {
		conn, err := mr.conn.Accept()
		if err != nil {
			mr.logger.Error("failed to accept connection:", err)
			continue
		}
		go mr.handleConnection(conn)
	}
}

func (mr *MessageReception) HandleConnection(conn net.Conn) {
	defer conn.Close()

	var msg Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&msg); err != nil {
		mr.logger.Error("failed to decode message:", err)
		return
	}

	if err := mr.validateMessage(&msg); err != nil {
		mr.logger.Error("message validation failed:", err)
		return
	}

	mr.mutex.Lock()
	mr.messageQueue <- msg
	mr.mutex.Unlock()

	mr.logger.Info("message received and queued from", conn.RemoteAddr())
}

func (mr *MessageReception) ValidateMessage(msg *common.Message) common.error {
	// Verify message signature
	if !VerifySignature(msg.Payload, msg.Signature, msg.Sender) {
		return NewCustomError(100, "invalid message signature", nil)
	}

	// Decrypt the message payload if required
	decryptedPayload, err := DecryptData(msg.Payload, msg.Receiver)
	if err != nil {
		return NewCustomError(200, "failed to decrypt message payload", nil)
	}
	msg.Payload = decryptedPayload

	return nil
}

func (mr *MessageReception) ProcessMessages() {
	for msg := range mr.messageQueue {
		if err := mr.processMessage(&msg); err != nil {
			mr.logger.Error("failed to process message:", err)
		}
	}
}

func (mr *MessageReception) ProcessMessage(msg *common.Message) common.error {
	mr.logger.Info("processing message from", msg.Sender)
	return nil
}

func (mr *MessageReception) StopServer() {
	mr.conn.Close()
	close(mr.messageQueue)
	mr.logger.Info("Message reception server stopped")
}

type MessageRouting struct {
	Logger      *common.Logger
	RouterTable map[string]net.Conn
}

func NewMessageRouting(logger *common.Logger) *MessageRouting {
	return &MessageRouting{
		Logger:      logger,
		RouterTable: make(map[string]net.Conn),
	}
}

func (mr *MessageRouting) RouteMessage(msg *common.Message, destNodeID string) common.error {
	conn, ok := mr.RouterTable[destNodeID]
	if !ok {
		return fmt.Errorf("no route to node %s", destNodeID)
	}

	encryptedMsg, err := mr.encryptMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	if _, err := conn.Write(encryptedMsg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	mr.Logger.Info("Message routed to node:", destNodeID)
	return nil
}

func (mr *MessageRouting) AddRoute(nodeID string, conn net.Conn) {
	mr.RouterTable[nodeID] = conn
	mr.Logger.Info("Route added for node:", nodeID)
}

func (mr *MessageRouting) RemoveRoute(nodeID string) {
	delete(mr.RouterTable, nodeID)
	mr.Logger.Info("Route removed for node:", nodeID)
}

func (mr *MessageRouting) EncryptMessage(msg *common.Message) ([]byte, common.error) {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, msgBytes, nil)
	encryptedMsg := append(key, ciphertext...)
	return encryptedMsg, nil
}

func (mr *MessageRouting) DecryptMessage(encryptedMsg []byte) (Message common.Message, error) {
	if len(encryptedMsg) < aes.BlockSize {
		return Message{}, errors.New("invalid encrypted message size")
	}

	key := encryptedMsg[:32]
	ciphertext := encryptedMsg[32:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return Message{}, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Message{}, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return Message{}, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	msgBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Message{}, fmt.Errorf("failed to decrypt message: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return msg, nil
}

func (mr *MessageRouting) HandleIncomingMessage(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		mr.Logger.Error("failed to read incoming message:", err)
		return
	}

	msg, err := mr.decryptMessage(buf[:n])
	if err != nil {
		mr.Logger.Error("failed to decrypt incoming message:", err)
		return
	}

	mr.Logger.Info("Received message from node:", msg.SourceNodeID)
}

func (mr *MessageRouting) SendMessage(msg *common.Message, destNodeID string) common.error {
	conn, ok := mr.RouterTable[destNodeID]
	if !ok {
		return fmt.Errorf("no route to node %s", destNodeID)
	}

	encryptedMsg, err := mr.encryptMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	if _, err := conn.Write(encryptedMsg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	mr.Logger.Info("Message sent to node:", destNodeID)
	return nil
}

func (mr *MessageRouting) BroadcastMessage(msg *common.Message) common.error {
	for nodeID, conn := range mr.RouterTable {
		if err := mr.SendMessage(msg, nodeID); err != nil {
			mr.Logger.Error("failed to send message to node:", nodeID, err)
		}
	}
	return nil
}


func (mv *MessageValidator) ValidateMessage(msg *common.Message) common.error {
	if err := mv.validateStructure(msg); err != nil {
		return fmt.Errorf("message structure validation failed: %w", err)
	}

	if err := mv.validateSignature(msg); err != nil {
		return fmt.Errorf("message signature validation failed: %w", err)
	}

	if err := mv.validateIntegrity(msg); err != nil {
		return fmt.Errorf("message integrity validation failed: %w", err)
	}

	mv.Logger.Info("Message validated successfully from node:", msg.SourceNodeID)
	return nil
}

func (mv *MessageValidator) ValidateMessageStructure(msg *common.Message) common.error {
	if msg.SourceNodeID == "" || msg.DestinationNodeID == "" || msg.Payload == nil {
		return errors.New("invalid message structure: missing required fields")
	}
	return nil
}

func (mv *MessageValidator) ValidateMessageSignature(msg *common.Message) common.error {
	publicKey, ok := mv.PublicKeyMap[msg.SourceNodeID]
	if !ok {
		return fmt.Errorf("public key not found for node %s", msg.SourceNodeID)
	}

	hashedPayload := sha256.Sum256(msg.Payload)
	if !VerifySignature(publicKey, hashedPayload[:], msg.Signature) {
		return errors.New("invalid message signature")
	}
	return nil
}

func (mv *MessageValidator) ValidateMessageIntegrity(msg *common.Message) common.error {
	expectedHash := sha256.Sum256(msg.Payload)
	if !equalHashes(expectedHash[:], msg.Hash) {
		return errors.New("message integrity check failed")
	}
	return nil
}

func equalHashes(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	return true
}

func GenerateMessageHash(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

func GenerateMessageSignature(payload []byte, privateKey string) ([]byte, common.error) {
	hashedPayload := sha256.Sum256(payload)
	signature, err := Sign(privateKey, hashedPayload[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate message signature: %w", err)
	}
	return signature, nil
}


func (qm *common.QoSManager) EncryptMessage(plainText, key string) (string, common.error) {
	keyHash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (qm *common.QoSManager) DecryptMessage(cipherText, key string) (string, common.error) {
	keyHash := sha256.Sum256([]byte(key))
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func (qm *common.QoSManager) UpdateTraffic(nodeID string, sent, received int) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	stat, exists := qm.trafficStats[nodeID]
	if !exists {
		stat = TrafficStat{}
	}

	stat.messagesSent += sent
	stat.messagesReceived += received
	stat.lastUpdated = time.Now()

	qm.trafficStats[nodeID] = stat
}

func (qm *common.QoSManager) GetTrafficStats(nodeID string) (TrafficStat common.TrafficStat, common.error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	stat, exists := qm.trafficStats[nodeID]
	if !exists {
		return TrafficStat{}, errors.New("node not found")
	}

	return stat, nil
}

func (qm *common.QoSManager) ApplyRateLimiting(nodeID string, messageCount int) bool {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	stat, exists := qm.trafficStats[nodeID]
	if !exists {
		stat = common.TrafficStat{}
	}

	now := time.Now()
	duration := now.Sub(stat.lastUpdated).Seconds()

	if duration > 1 {
		stat.messagesSent = 0
		stat.lastUpdated = now
	}

	if stat.messagesSent+messageCount > qm.rateLimit {
		if stat.messagesSent < qm.burstLimit {
			stat.messagesSent += messageCount
			qm.trafficStats[nodeID] = stat
			return true
		}
		log.Println(fmt.Sprintf("Rate limit exceeded for node %s", nodeID))
		return false
	}

	stat.messagesSent += messageCount
	qm.trafficStats[nodeID] = stat
	return true
}

func (qm *common.QoSManager) SetPriority(nodeID string, priority int) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.priorityLevels[nodeID] = priority
}

func (qm *common.QoSManager) GetPriority(nodeID string) (int, common.error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	priority, exists := qm.priorityLevels[nodeID]
	if !exists {
		return 0, errors.New("node not found")
	}

	return priority, nil
}

func (qm *common.QoSManager) AdjustRateLimits() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.rateLimit += 10
	qm.burstLimit += 5
}

func (qm *common.QoSManager) LogTraffic() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	for nodeID, stat := range qm.trafficStats {
		log.Println(fmt.Sprintf("Node %s: Sent=%d, Received=%d, LastUpdated=%s",
			nodeID, stat.messagesSent, stat.messagesReceived, stat.lastUpdated))
	}
}

func (qm *common.QoSManager) MonitorNetwork() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		qm.AdjustRateLimits()
		qm.LogTraffic()
	}
}


func (em *common.EncryptionManager) Encrypt(data []byte) ([]byte, common.error) {
	// Example encryption logic
	key := []byte("examplekey123456") // Replace with a proper key management system
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (em *common.EncryptionManager) Decrypt(data []byte) ([]byte, common.error) {
	// Example decryption logic
	key := []byte("examplekey123456") // Replace with a proper key management system
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}



func (sm *common.SecurityManager) ValidateMessage(data []byte) common.error {
	// Example security validation logic
	return nil
}


func GenerateResponse(id, status string, data []byte, privateKey *common.rsa.PrivateKey) (Response *common.Response, common.error) {
	response := &Response{
		ID:        id,
		Timestamp: time.Now(),
		Status:    status,
		Data:      data,
	}

	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}
	response.Signature = signature

	encryptedData, err := EncryptData(response.Data, response.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt response: %w", err)
	}
	response.Data = encryptedData

	return response, nil
}

func VerifyResponseSignature(response *common.Response, publicKey *common.rsa.PublicKey) common.error {
	hash := sha256.Sum256(response.Data)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], response.Signature); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

func ValidateResponse(response *common.Response) common.error {
	if time.Since(response.Timestamp) > 5*time.Minute {
		return errors.New("response is too old")
	}

	if response.Status != "success" && response.Status != "error" {
		return errors.New("invalid response status")
	}

	return nil
}

