package node_connectivity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
	"golang.org/x/crypto/scrypt"
)

// NodeConnectivityManager manages the connectivity status of nodes
type NodeConnectivityManager struct {
	nodes map[string]*NodeStatus
	mutex sync.Mutex
}

// NodeStatus represents the connectivity status of a node
type NodeStatus struct {
	NodeID    string    `json:"node_id"`
	IP        string    `json:"ip"`
	Port      string    `json:"port"`
	Connected bool      `json:"connected"`
	LastCheck time.Time `json:"last_check"`
}

// NewNodeConnectivityManager initializes and returns a new NodeConnectivityManager object
func NewNodeConnectivityManager() *NodeConnectivityManager {
	return &NodeConnectivityManager{
		nodes: make(map[string]*NodeStatus),
	}
}

// AddNode adds a new node to the connectivity manager
func (ncm *NodeConnectivityManager) AddNode(nodeID, ip, port string) {
	ncm.mutex.Lock()
	defer ncm.mutex.Unlock()
	ncm.nodes[nodeID] = &NodeStatus{
		NodeID:    nodeID,
		IP:        ip,
		Port:      port,
		Connected: false,
		LastCheck: time.Time{},
	}
	log.Printf("Added node %s with IP %s and port %s\n", nodeID, ip, port)
}

// RemoveNode removes a node from the connectivity manager
func (ncm *NodeConnectivityManager) RemoveNode(nodeID string) {
	ncm.mutex.Lock()
	defer ncm.mutex.Unlock()
	delete(ncm.nodes, nodeID)
	log.Printf("Removed node %s\n", nodeID)
}

// CheckNodeConnectivity checks the connectivity of a specific node
func (ncm *NodeConnectivityManager) CheckNodeConnectivity(nodeID string) bool {
	ncm.mutex.Lock()
	node, exists := ncm.nodes[nodeID]
	ncm.mutex.Unlock()

	if !exists {
		log.Printf("Node %s does not exist\n", nodeID)
		return false
	}

	address := net.JoinHostPort(node.IP, node.Port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		ncm.updateNodeStatus(nodeID, false)
		log.Printf("Node %s is not reachable: %v\n", nodeID, err)
		return false
	}
	defer conn.Close()

	ncm.updateNodeStatus(nodeID, true)
	log.Printf("Node %s is reachable\n", nodeID)
	return true
}

// CheckAllNodesConnectivity checks the connectivity of all nodes
func (ncm *NodeConnectivityManager) CheckAllNodesConnectivity() {
	ncm.mutex.Lock()
	nodes := make(map[string]*NodeStatus)
	for k, v := range ncm.nodes {
		nodes[k] = v
	}
	ncm.mutex.Unlock()

	var wg sync.WaitGroup
	for nodeID := range nodes {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			ncm.CheckNodeConnectivity(id)
		}(nodeID)
	}
	wg.Wait()
}

// GetNodeStatus retrieves the status of a specific node
func (ncm *NodeConnectivityManager) GetNodeStatus(nodeID string) *NodeStatus {
	ncm.mutex.Lock()
	defer ncm.mutex.Unlock()
	return ncm.nodes[nodeID]
}

// GetAllNodesStatus retrieves the status of all nodes
func (ncm *NodeConnectivityManager) GetAllNodesStatus() []*NodeStatus {
	ncm.mutex.Lock()
	defer ncm.mutex.Unlock()
	statuses := make([]*NodeStatus, 0, len(ncm.nodes))
	for _, status := range ncm.nodes {
		statuses = append(statuses, status)
	}
	return statuses
}

// updateNodeStatus updates the connectivity status of a node
func (ncm *NodeConnectivityManager) updateNodeStatus(nodeID string, connected bool) {
	ncm.mutex.Lock()
	defer ncm.mutex.Unlock()
	if node, exists := ncm.nodes[nodeID]; exists {
		node.Connected = connected
		node.LastCheck = time.Now()
	}
}

// ServeHTTP serves the connectivity status of nodes via HTTP
func (ncm *NodeConnectivityManager) ServeHTTP(port string) {
	http.HandleFunc("/nodes", ncm.handleNodesRequest)
	log.Printf("Serving node connectivity status on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// handleNodesRequest handles HTTP requests for node connectivity status
func (ncm *NodeConnectivityManager) handleNodesRequest(w http.ResponseWriter, r *http.Request) {
	nodes := ncm.GetAllNodesStatus()
	data, err := json.Marshal(nodes)
	if err != nil {
		http.Error(w, "Failed to marshal nodes status", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Real-time Alerts
type AlertManager struct {
	alertThreshold int
	alertChan      chan string
}

// NewAlertManager initializes and returns a new AlertManager object
func NewAlertManager(threshold int) *AlertManager {
	return &AlertManager{
		alertThreshold: threshold,
		alertChan:      make(chan string),
	}
}

// StartMonitoring starts the alert monitoring process for node connectivity
func (am *AlertManager) StartMonitoring(ncm *NodeConnectivityManager) {
	go func() {
		for {
			time.Sleep(1 * time.Minute) // Check every minute
			am.checkForAlerts(ncm)
		}
	}()
}

// checkForAlerts checks the node connectivity status and sends alerts if necessary
func (am *AlertManager) checkForAlerts(ncm *NodeConnectivityManager) {
	nodes := ncm.GetAllNodesStatus()
	disconnectedNodes := 0
	for _, node := range nodes {
		if !node.Connected {
			disconnectedNodes++
		}
	}
	if disconnectedNodes >= am.alertThreshold {
		alert := am.createAlert(disconnectedNodes)
		log.Println(alert)
		am.alertChan <- alert
	}
}

// createAlert creates an alert message based on the number of disconnected nodes
func (am *AlertManager) createAlert(disconnectedNodes int) string {
	return log.Sprintf("Alert: %d nodes are disconnected", disconnectedNodes)
}

// GetAlertChannel returns the alert channel
func (am *AlertManager) GetAlertChannel() <-chan string {
	return am.alertChan
}

// SecureCommunicator handles encryption and decryption of communication
type SecureCommunicator struct {
	key []byte
}

// NewSecureCommunicator initializes and returns a new SecureCommunicator object
func NewSecureCommunicator(passphrase string) (*SecureCommunicator, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return &SecureCommunicator{key: key}, nil
}

// Encrypt encrypts data using AES
func (sc *SecureCommunicator) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES
func (sc *SecureCommunicator) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// PeerCommunicator manages peer-to-peer communication and data exchange
type PeerCommunicator struct {
	ncm             *NodeConnectivityManager
	secureComm      *SecureCommunicator
	communicationCh chan *PeerMessage
}

// PeerMessage represents a message exchanged between peers
type PeerMessage struct {
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	Data       []byte `json:"data"`
	Timestamp  int64  `json:"timestamp"`
}

// NewPeerCommunicator initializes and returns a new PeerCommunicator
func NewPeerCommunicator(ncm *NodeConnectivityManager, secureComm *SecureCommunicator) *PeerCommunicator {
	return &PeerCommunicator{
		ncm:             ncm,
		secureComm:      secureComm,
		communicationCh: make(chan *PeerMessage),
	}
}

// SendMessage sends an encrypted message to a peer
func (pc *PeerCommunicator) SendMessage(fromNodeID, toNodeID string, data []byte) error {
	encryptedData, err := pc.secureComm.Encrypt(data)
	if err != nil {
		return err
	}
	message := &PeerMessage{
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
		Data:       encryptedData,
		Timestamp:  time.Now().Unix(),
	}
	pc.communicationCh <- message
	return nil
}

// ReceiveMessage receives a message from the communication channel and decrypts it
func (pc *PeerCommunicator) ReceiveMessage() (*PeerMessage, error) {
	message := <-pc.communicationCh
	decryptedData, err := pc.secureComm.Decrypt(message.Data)
	if err != nil {
		return nil, err
	}
	message.Data = decryptedData
	return message, nil
}

// BroadcastMessage sends an encrypted message to all connected peers
func (pc *PeerCommunicator) BroadcastMessage(fromNodeID string, data []byte) {
	encryptedData, err := pc.secureComm.Encrypt(data)
	if err != nil {
		log.Println("Failed to encrypt data for broadcast:", err)
		return
	}
	pc.ncm.mutex.Lock()
	for nodeID, status := range pc.ncm.nodes {
		if status.Connected && nodeID != fromNodeID {
			message := &PeerMessage{
				FromNodeID: fromNodeID,
				ToNodeID:   nodeID,
				Data:       encryptedData,
				Timestamp:  time.Now().Unix(),
			}
			pc.communicationCh <- message
		}
	}
	pc.ncm.mutex.Unlock()
}

// HandlePeerCommunication handles incoming peer communication
func (pc *PeerCommunicator) HandlePeerCommunication() {
	go func() {
		for {
			message := <-pc.communicationCh
			log.Printf("Received message from %s to %s at %d\n", message.FromNodeID, message.ToNodeID, message.Timestamp)
			// Process the message as needed
		}
	}()
}

// CLI and SDK additions are necessary to manage nodes, send/receive messages, and monitor connectivity
func main() {
	// Example usage
	ncm := NewNodeConnectivityManager()
	secureComm, err := NewSecureCommunicator("securepassphrase")
	if err != nil {
		log.Fatalf("Failed to initialize secure communicator: %v\n", err)
	}
	pc := NewPeerCommunicator(ncm, secureComm)
	ncm.AddNode("node1", "127.0.0.1", "8080")
	ncm.AddNode("node2", "127.0.0.2", "8080")

	pc.HandlePeerCommunication()

	err = pc.SendMessage("node1", "node2", []byte("Hello, Node 2!"))
	if err != nil {
		log.Fatalf("Failed to send message: %v\n", err)
	}

	message, err := pc.ReceiveMessage()
	if err != nil {
		log.Fatalf("Failed to receive message: %v\n", err)
	}
	log.Printf("Decrypted message: %s\n", string(message.Data))
}
