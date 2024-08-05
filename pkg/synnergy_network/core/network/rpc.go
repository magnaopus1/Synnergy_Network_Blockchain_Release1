package network

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)



func (c *common.RPCClient) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	requestID := generateRequestID()
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  method,
		"params":  params,
	}

	c.mu.Lock()
	err := c.conn.WriteJSON(request)
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case response := <-c.receiveResponse(requestID):
		if response.Error != nil {
			return fmt.Errorf("RPC error %d: %s", response.Error.Code, response.Error.Message)
		}
		return json.Unmarshal(response.Result, result)
	}
}

func (c *common.RPCClient) receiveResponse(requestID string) <-chan (RPCResponse *common.RPCResponse) {
	ch := make(chan *commonRPCResponse)
	go func() {
		for {
			var response RPCResponse
			if err := c.conn.ReadJSON(&response); err != nil {
				log.Printf("failed to read response: %v", err)
				continue
			}
			if response.ID == requestID {
				ch <- &response
				break
			}
		}
	}()
	return ch
}

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}



func (s *common.RPCServer) RegisterMethod(method string, handler func(context.Context, json.RawMessage) (interface{}, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = handler
}

func (s *common.RPCServer) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	response := s.handleRequest(r.Context(), request)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("failed to send response: %v", err)
	}
}

func (s *common.RPCServer) handleRequest(ctx context.Context, request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}) *common.RPCResponse {
	s.mu.Lock()
	handler, exists := s.handlers[request.Method]
	s.mu.Unlock()
	if !exists {
		return &common.RPCResponse{
			ID: request.ID,
			Error: &RPCError{
				Code:    -32601,
				Message: "method not found",
			},
		}
	}

	result, err := handler(ctx, request.Params)
	if err != nil {
		return &common.RPCResponse{
			ID: request.ID,
			Error: &RPCError{
				Code:    -32000,
				Message: err.Error(),
			},
		}
	}

	return &common.RPCResponse{
		ID:     request.ID,
		Result: result,
	}
}

func (s *common.RPCServer) Start() error {
	return s.server.ListenAndServeTLS("", "")
}

func (s *common.RPCServer) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// Secure communication with encryption
func SecureConnection(conn *websocket.Conn, encryptionMethod, key string) error {
	switch encryptionMethod {
	case "AES":
		aesContext, err := NewAESContext(key)
		if err != nil {
			return fmt.Errorf("failed to set up AES encryption: %v", err)
		}
		conn.SetReadLimit(aesContext.ReadLimit())
		conn.SetWriteLimit(aesContext.WriteLimit())
	case "Scrypt":
		scryptContext, err := NewScryptContext(key)
		if err != nil {
			return fmt.Errorf("failed to set up Scrypt encryption: %v", err)
		}
		conn.SetReadLimit(scryptContext.ReadLimit())
		conn.SetWriteLimit(scryptContext.WriteLimit())
	case "Argon2":
		argon2Context, err := NewArgon2Context(key)
		if err != nil {
			return fmt.Errorf("failed to set up Argon2 encryption: %v", err)
		}
		conn.SetReadLimit(argon2Context.ReadLimit())
		conn.SetWriteLimit(argon2Context.WriteLimit())
	default:
		return fmt.Errorf("unsupported encryption method: %s", encryptionMethod)
	}
	return nil
}



func (c *common.BatchRPCClient) Call(method string, params interface{}) (*common.RPCResponse, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %w", err)
	}

	encryptedParams, err := c.encryptData(paramBytes)
	if err != nil {
		return nil, err
	}

	call := &common.RPCCall{
		ID:     time.Now().UnixNano(),
		Method: method,
		Params: encryptedParams,
	}

	if c.BatchingEnabled {
		return c.addToBatch(call)
	}
	return c.sendCall(call)
}

func (c *common.BatchRPCClient) addToBatch(call *common.RPCCall) (*common.RPCResponse, error) {
	c.batchMux.Lock()
	defer c.batchMux.Unlock()

	if c.pendingBatch == nil {
		c.pendingBatch = &common.RPCBatch{
			Calls:    []*common.RPCCall{},
			Response: make(chan *common.RPCResponse, 1),
		}
		go c.sendBatch()
	}

	c.pendingBatch.Calls = append(c.pendingBatch.Calls, call)
	if len(c.pendingBatch.Calls) >= c.BatchSize {
		c.sendBatchNow()
	}

	select {
	case res := <-c.pendingBatch.Response:
		return res, nil
	case <-time.After(c.BatchInterval):
		return nil, errors.New("timeout waiting for batch response")
	}
}

func (c *common.BatchRPCClient) sendBatchNow() {
	c.batchMux.Lock()
	defer c.batchMux.Unlock()

	if c.pendingBatch != nil && len(c.pendingBatch.Calls) > 0 {
		go c.sendBatch()
	}
}

func (c *common.BatchRPCClient) sendBatch() {
	c.batchMux.Lock()
	defer c.batchMux.Unlock()

	if c.pendingBatch == nil || len(c.pendingBatch.Calls) == 0 {
		return
	}

	batch := c.pendingBatch
	c.pendingBatch = nil

	batchBytes, err := json.Marshal(batch.Calls)
	if err != nil {
		log.Printf("failed to marshal batch: %v", err)
		return
	}

	req, err := http.NewRequest("POST", c.URL, bytes.NewBuffer(batchBytes))
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("failed to send batch request: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return
	}

	var responses []*common.RPCResponse
	if err := json.Unmarshal(body, &responses); err != nil {
		log.Printf("failed to unmarshal batch response: %v", err)
		return
	}

	batch.ResponseMux.Lock()
	for _, res := range responses {
		batch.Response <- res
	}
	batch.ResponseMux.Unlock()
}

func (c *common.BatchRPCClient) sendCall(call *common.RPCCall) (*common.RPCResponse, error) {
	encryptedCall, err := c.encryptData(call.Params)
	if err != nil {
		return nil, err
	}
	call.Params = encryptedCall

	callBytes, err := json.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal call: %w", err)
	}

	req, err := http.NewRequest("POST", c.URL, bytes.NewBuffer(callBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var rpcResp common.RPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	decryptedResult, err := c.decryptData(rpcResp.Result)
	if err != nil {
		return nil, err
	}
	rpcResp.Result = decryptedResult

	return &rpcResp, nil
}

func (c *common.BatchRPCClient) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(c.encryptionKey))
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)
	return encrypted, nil
}

func (c *common.BatchRPCClient) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(c.encryptionKey))
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
}

// Close closes the client connection
func (c *common.Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connection.Close()
}

// SendRequest sends an RPC request to the server
func (c *common.Client) SendRequest(request []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	encryptedRequest, err := EncryptWithPublicKey(request, &c.encryptionKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}

	_, err = c.connection.Write(encryptedRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	response := make([]byte, 4096)
	n, err := c.connection.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	decryptedResponse, err := DecryptWithPrivateKey(response[:n], c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	return decryptedResponse, nil
}

// EncryptWithPublicKey encrypts data using the public key
func EncryptWithPublicKey(data []byte, pub *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, data, label)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data using the private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}





// RegisterUser registers a new user in the system
func (a *common.AuthProvider) RegisterUser(username, password, role string) (string, error) {
	if _, exists := a.users[username]; exists {
		return "", errors.New("user already exists")
	}

	// Securely hash the password
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashedPassword, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	a.users[username] = &User{
		Username: username,
		Password: base64.StdEncoding.EncodeToString(hashedPassword),
		Role:     role,
		Token:    "",
	}
	return "User registered successfully", nil
}

// AuthenticateUser authenticates a user and returns a token
func (a *common.AuthProvider) AuthenticateUser(username, password string) (string, error) {
	user, exists := a.users[username]
	if !exists {
		return "", errors.New("user not found")
	}
	hashedPassword, err := base64.StdEncoding.DecodeString(user.Password)
	if err != nil {
		return "", err
	}
	providedPasswordHash, err := scrypt.Key([]byte(password), hashedPassword[:16], 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	if !sha256.Equal(hashedPassword, providedPasswordHash) {
		return "", errors.New("incorrect password")
	}
	token := generateToken()
	user.Token = token
	return token, nil
}

// ValidateToken validates the provided token
func (a *common.AuthProvider) ValidateToken(token string) (*User, error) {
	for _, user := range a.users {
		if user.Token == token {
			return user, nil
		}
	}
	return nil, errors.New("invalid token")
}

// loadOrGenerateKeys loads or generates RSA keys for the server
func (a *common.AuthProvider) loadOrGenerateKeys() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	a.privateKey = privateKey
	a.publicKey = &privateKey.PublicKey
	return nil
}

// generateToken generates a new random token for user authentication
func generateToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.StdEncoding.EncodeToString(token)
}

// RPC methods implementation

// GetBlockchainInfo retrieves blockchain information
func (s *common.RPCServer) GetBlockchainInfo(ctx context.Context, req *BlockchainInfoRequest) (*BlockchainInfoResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}
	if user.Role != "admin" {
		return nil, status.Error(http.StatusForbidden, "insufficient permissions")
	}

	// Fetch blockchain information
	info, err := GetBlockchainInfo()
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to fetch blockchain info")
	}

	return &BlockchainInfoResponse{Info: info}, nil
}

// AddTransaction adds a new transaction to the blockchain
func (s *common.RPCServer) AddTransaction(ctx context.Context, req *TransactionRequest) (*TransactionResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	// Validate and add transaction
	txID, err := AddTransaction(req.Transaction)
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to add transaction")
	}

	return &TransactionResponse{TxID: txID}, nil
}

// GetTransaction retrieves a transaction by ID
func (s *common.RPCServer) GetTransaction(ctx context.Context, req *GetTransactionRequest) (*GetTransactionResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	// Fetch transaction details
	transaction, err := GetTransaction(req.TxID)
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to fetch transaction")
	}

	return &GetTransactionResponse{Transaction: transaction}, nil
}

// ListTransactions lists transactions with pagination
func (s *common.RPCServer) ListTransactions(ctx context.Context, req *ListTransactionsRequest) (*ListTransactionsResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	// Fetch transactions
	transactions, err := ListTransactions(req.Page, req.PageSize)
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to list transactions")
	}

	return &ListTransactionsResponse{Transactions: transactions}, nil
}

// GenerateKeys generates a new key pair for a user
func (s *common.RPCServer) GenerateKeys(ctx context.Context, req *GenerateKeysRequest) (*GenerateKeysResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to generate keys")
	}

	return &GenerateKeysResponse{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

// EncryptData encrypts data using the user's public key
func (s *common.RPCServer) EncryptData(ctx context.Context, req *EncryptDataRequest) (*EncryptDataResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	publicKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		return nil, status.Error(http.StatusBadRequest, "invalid public key")
	}

	encryptedData, err := EncryptWithPublicKey(req.Data, publicKey)
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to encrypt data")
	}

	return &EncryptDataResponse{EncryptedData: encryptedData}, nil
}

// DecryptData decrypts data using the user's private key
func (s *common.RPCServer) DecryptData(ctx context.Context, req *DecryptDataRequest) (*DecryptDataResponse, error) {
	user, err := s.authProvider.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Error(http.StatusUnauthorized, "unauthorized")
	}

	privateKey, err := base64.StdEncoding.DecodeString(req.PrivateKey)
	if err != nil {
		return nil, status.Error(http.StatusBadRequest, "invalid private key")
	}

	decryptedData, err := DecryptWithPrivateKey(req.EncryptedData, privateKey)
	if err != nil {
		return nil, status.Error(http.StatusInternalServerError, "failed to decrypt data")
	}

	return &DecryptDataResponse{DecryptedData: decryptedData}, nil
}



// AddConnection adds a new connection to the list
func (cl *common.ConnectionList) AddConnection(id, address string, encryptionKey []byte) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.connections[id]; exists {
		return fmt.Errorf("connection with ID %s already exists", id)
	}

	connection := &common.Connection{
		ID:           id,
		Address:      address,
		Status:       "active",
		LastActive:   0, // This should be updated with actual timestamp
		EncryptionKey: encryptionKey,
	}

	cl.connections[id] = connection
	return nil
}

// RemoveConnection removes a connection from the list
func (cl *common.ConnectionList) RemoveConnection(id string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.connections[id]; !exists {
		return fmt.Errorf("connection with ID %s does not exist", id)
	}

	delete(cl.connections, id)
	return nil
}

// GetConnection retrieves a connection by ID
func (cl *common.ConnectionList) GetConnection(id string) (*common.Connection, error) {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	connection, exists := cl.connections[id]
	if !exists {
		return nil, fmt.Errorf("connection with ID %s not found", id)
	}

	return connection, nil
}



// ListConnections lists all active connections
func (cl *common.ConnectionList) ListConnections() []common.Connection {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	connections := make([]Connection, 0, len(cl.connections))
	for _, conn := range cl.connections {
		connections = append(connections, *conn)
	}

	return connections
}

// UpdateLastActive updates the last active timestamp for a connection
func (cl *common.ConnectionList) UpdateLastActive(id string, timestamp int64) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	connection, exists := cl.connections[id]
	if !exists {
		return fmt.Errorf("connection with ID %s not found", id)
	}

	connection.LastActive = timestamp
	return nil
}

// UpdateStatus updates the status of a connection
func (cl *common.ConnectionList) UpdateStatus(id, status string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	connection, exists := cl.connections[id]
	if !exists {
		return fmt.Errorf("connection with ID %s not found", id)
	}

	connection.Status = status
	return nil
}

// exchangeSessionKeys exchanges the session keys between peers.
func (channel *common.SecureRPCChannel) exchangeSessionKeys() error {
	encryptedSessionKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, channel.peerPublicKey, channel.sessionKey, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt session key: %v", err)
	}

	err = SendData(channel.conn, encryptedSessionKey)
	if err != nil {
		return fmt.Errorf("failed to send encrypted session key: %v", err)
	}

	response, err := ReceiveData(channel.conn)
	if err != nil {
		return fmt.Errorf("failed to receive encrypted session key: %v", err)
	}

	decryptedSessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, channel.privateKey, response, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt session key: %v", err)
	}

	if !Equal(decryptedSessionKey, channel.sessionKey) {
		return errors.New("session key mismatch")
	}

	return nil
}

// EncryptMessage encrypts a message using AES encryption.
func (channel *common.SecureRPCChannel) EncryptMessage(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(channel.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptMessage decrypts a message using AES encryption.
func (channel *common.SecureRPCChannel) DecryptMessage(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(channel.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}

// SendMessage sends an encrypted message over the RPC channel.
func (channel *common.SecureRPCChannel) SendMessage(msg common.Message) error {
	plaintext, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	ciphertext, err := channel.EncryptMessage(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	err = SendData(channel.conn, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to send encrypted message: %v", err)
	}

	return nil
}

// ReceiveMessage receives an encrypted message over the RPC channel.
func (channel *common.SecureRPCChannel) ReceiveMessage() (common.Message, error) {
	ciphertext, err := ReceiveData(channel.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive encrypted message: %v", err)
	}

	plaintext, err := channel.DecryptMessage(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	msg, err := Deserialize(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize message: %v", err)
	}

	return msg, nil
}

// Close closes the RPC channel.
func (channel *common.SecureRPCChannel) Close() error {
	return channel.conn.Close()
}


// Start starts the RPC server.
func (s *common.RPCSetup) Start() error {
	s.logger.Info("Starting RPC server...")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.logger.Error("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *common.RPCSetup) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	s.logger.Info("New connection from %s", clientAddr)

	// Rate limiting
	if !s.rateLimiter.Allow(clientAddr) {
		s.logger.Warn("Rate limit exceeded for %s", clientAddr)
		return
	}

	// Authentication
	if err := s.authenticator.Authenticate(conn); err != nil {
		s.logger.Warn("Authentication failed for %s: %v", clientAddr, err)
		return
	}

	// Access control
	if !s.accessControl.IsAllowed(clientAddr) {
		s.logger.Warn("Access denied for %s", clientAddr)
		return
	}

	// Encryption setup
	if err := s.encryption.SetupConnection(conn); err != nil {
		s.logger.Error("Encryption setup failed for %s: %v", clientAddr, err)
		return
	}

	rpc.ServeConn(conn)
}

// Stop stops the RPC server.
func (s *common.RPCSetup) Stop() {
	s.logger.Info("Stopping RPC server...")
	s.listener.Close()
	for _, client := range s.clients {
		client.Close()
	}
}

// RegisterService registers an RPC service.
func (s *common.RPCSetup) RegisterService(service interface{}, name string) error {
	return rpc.RegisterName(name, service)
}



func (c *common.RPCClient) setupConnection() error {
	// Perform encryption setup
	if err := c.encryption.SetupConnection(c.conn); err != nil {
		return fmt.Errorf("failed to setup encryption: %v", err)
	}

	// Perform authentication
	if err := c.auth.Authenticate(c.conn); err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	return nil
}

// Call invokes an RPC method.
func (c *common.RPCClient) Call(serviceMethod string, args interface{}, reply interface{}) error {
	return c.conn.Call(serviceMethod, args, reply)
}

// Close closes the RPC client connection.
func (c *common.RPCClient) Close() error {
	return c.conn.Close()
}

func generateKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	return key
}

// Authenticate performs authentication over the connection.
func (a *common.Authenticator) Authenticate(conn net.Conn) error {
	// Simple authentication logic (to be extended as needed)
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return err
	}

	_, err := conn.Write(challenge)
	if err != nil {
		return err
	}

	response := make([]byte, 32)
	if _, err := conn.Read(response); err != nil {
		return err
	}

	if !a.validateResponse(challenge, response) {
		return errors.New("authentication failed")
	}

	return nil
}

func (a *common.Authenticator) validateResponse(challenge, response []byte) bool {
	expected := sha256.Sum256(append(challenge, a.key...))
	return hmac.Equal(response, expected[:])
}

