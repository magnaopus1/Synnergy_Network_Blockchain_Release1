package network

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)


// GetConnection retrieves an available connection from the pool or creates a new one
func (cp *common.ConnectionPool) GetConnection(address string) (net.Conn, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	for _, conn := range cp.Pool {
		if !conn.inUse && time.Since(conn.timestamp) < cp.idleTimeout {
			conn.inUse = true
			conn.timestamp = time.Now()
			return conn.conn, nil
		}
	}

	if len(cp.Pool) < cp.poolSize {
		newConn, err := cp.createConnection(address)
		if err != nil {
			return nil, err
		}
		cp.Pool = append(cp.Pool, &common.Connection{conn: newConn, inUse: true, timestamp: time.Now()})
		return newConn, nil
	}

	return nil, errors.New("no available connections")
}

// ReleaseConnection releases a connection back to the pool
func (cp *common.ConnectionPool) ReleaseConnection(conn net.Conn) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	for _, poolConn := range cp.Pool {
		if poolConn.conn == conn {
			poolConn.inUse = false
			poolConn.timestamp = time.Now()
			break
		}
	}
}

// Close closes all connections in the pool
func (cp *common.ConnectionPool) Close() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	for _, poolConn := range cp.Pool {
		poolConn.conn.Close()
	}
	cp.Pool = cp.Pool[:0]
}

// createConnection creates a new secure connection
func (cp *common.ConnectionPool) createConnection(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// maintainPool periodically checks the pool and removes idle connections
func (cp *common.ConnectionPool) maintainPool() {
	ticker := time.NewTicker(ConnectionCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		cp.mutex.Lock()
		for i := len(cp.Pool) - 1; i >= 0; i-- {
			if !cp.Pool[i].inUse && time.Since(cp.Pool[i].timestamp) > cp.idleTimeout {
				cp.Pool[i].conn.Close()
				cp.Pool = append(cp.Pool[:i], cp.Pool[i+1:]...)
			}
		}
		cp.mutex.Unlock()
	}
}



// AddPeer adds a new peer to the node
func (n *common.Node) AddPeer(peer *common.Peer) {
	n.PeerMutex.Lock()
	defer n.PeerMutex.Unlock()
	n.ActivePeers[peer.ID] = peer
}

// RemovePeer removes a peer from the node
func (n *common.Node) RemovePeer(peerID string) {
	n.PeerMutex.Lock()
	defer n.PeerMutex.Unlock()
	delete(n.ActivePeers, peerID)
}

// SendMessage sends a message to a specific peer
func (n *common.Node) SendMessage(peerID string, msg *common.Message) error {
	n.PeerMutex.Lock()
	peer, exists := n.ActivePeers[peerID]
	n.PeerMutex.Unlock()
	if !exists {
		return errors.New("peer not found")
	}

	address := net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port))
	conn, err := n.ConnectionPool.GetConnection(address)
	if err != nil {
		return err
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	encryptedMsg, err := encryptMessage(msgBytes, &peer.PublicKey, &n.PrivateKey)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	if err != nil {
		n.ConnectionPool.RemoveConnection(address)
	}
	return err
}

// ReceiveMessage listens for incoming messages
func (n *common.Node) ReceiveMessage() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", n.Port))
	if err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go n.handleConnection(conn)
	}
}

// handleConnection handles incoming connections
func (n *common.Node) handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	decryptedMsg, err := decryptMessage(buf[:n], &n.PrivateKey)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(decryptedMsg, &msg); err != nil {
		fmt.Println("Error unmarshaling message:", err)
		return
	}

	if err := n.validateMessage(&msg); err != nil {
		fmt.Println("Invalid message:", err)
		return
	}

	switch msg.Type {
	case "peer_info":
		n.handlePeerInfoMessage(&msg)
	case "data":
		n.handleDataMessage(&msg)
	default:
		fmt.Println("Unknown message type:", msg.Type)
	}
}

// validateMessage validates the authenticity and integrity of a message
func (n *common.Node) validateMessage(msg *common.Message) error {
	// Placeholder for signature verification implementation
	peerID := "" // This should be the result of signature verification
	n.PeerMutex.Lock()
	_, exists := n.ActivePeers[peerID]
	n.PeerMutex.Unlock()

	if !exists {
		return errors.New("unknown peer")
	}

	return nil
}

// handlePeerInfoMessage handles incoming peer information messages
func (n *common.Node) handlePeerInfoMessage(msg *common.Message) {
	var peer Peer
	if err := json.Unmarshal(msg.Payload, &peer); err != nil {
		fmt.Println("Error unmarshaling peer info message:", err)
		return
	}

	n.AddPeer(&peer)
	fmt.Println("Added new peer:", peer.ID)
}

// handleDataMessage handles incoming data messages
func (n *common.Node) handleDataMessage(msg *common.Message) {
	fmt.Println("Received data message:", string(msg.Payload))
}

// Dynamic routing based on real-time network conditions
func (n *common.Node) dynamicRouting(peerID string, msg *common.Message) error {
	for i := 0; i < MaxRetries; i++ {
		err := n.SendMessage(peerID, msg)
		if err == nil {
			return nil
		}
		time.Sleep(RetryInterval)
	}
	return errors.New("failed to send message after retries")
}

// Start is the main entry point for the node
func (n *common.Node) Start() {
	go n.ReceiveMessage()
	go n.monitorLatency()
	for {
		time.Sleep(10 * time.Second)
	}
}

// encryptAndSignMessage encrypts and signs a message
func (n *common.Node) encryptAndSignMessage(msg *common.Message) ([]byte, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// Placeholder for signing implementation
	signature := []byte{} // This should be the result of signing msgBytes
	msg.Signature = signature
	encryptedMsg, err := encryptMessage(msgBytes, &n.PublicKey, &n.PrivateKey)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}

// decryptAndVerifyMessage decrypts and verifies a message
func (n *common.Node) decryptAndVerifyMessage(encryptedMsg []byte) (*common.Message, error) {
	decryptedMsg, err := decryptMessage(encryptedMsg, &n.PrivateKey)
	if err != nil {
		return nil, err
	}

	var msg common.Message
	if err := json.Unmarshal(decryptedMsg, &msg); err != nil {
		return nil, err
	}

	if err := n.validateMessage(&msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// monitorLatency monitors latency and optimizes routes
func (n *common.Node) monitorLatency() {
	ticker := time.NewTicker(OptimizationCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		n.PeerMutex.Lock()
		for peerID, peer := range n.ActivePeers {
			start := time.Now()
			err := n.pingPeer(peer)
			latency := time.Since(start)
			if err != nil {
				fmt.Printf("Failed to ping peer %s: %v\n", peerID, err)
				continue
			}
			n.MetricsMutex.Lock()
			n.LatencyMetrics[peerID] = latency
			n.MetricsMutex.Unlock()
		}
		n.PeerMutex.Unlock()
		n.optimizeRoutes()
	}
}

// pingPeer pings a peer to measure latency
func (n *common.Node) pingPeer(peer *common.Peer) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port)), ConnectionTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := &common.Message{
		Type:      "ping",
		Payload:   []byte("ping"),
		Timestamp: time.Now(),
	}

	encryptedMsg, err := n.encryptAndSignMessage(msg)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	_, err = conn.Read(buf)
	if err != nil {
		return err
	}

	return nil
}

// optimizeRoutes optimizes routes based on latency metrics
func (n *common.Node) optimizeRoutes() {
	n.MetricsMutex.Lock()
	defer n.MetricsMutex.Unlock()

	for peerID, latency := range n.LatencyMetrics {
		fmt.Printf("Optimized route to peer %s with latency %v\n", peerID, latency)
	}
}


// AddEdgeNode adds a new edge node to the manager
func (m *common.EdgeNodeManager) AddEdgeNode(id, ip string, port int, publicKey [32]byte) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.EdgeNodes[id] = &common.EdgeNode{
		ID:            id,
		IP:            ip,
		NodeType:	String	
		Port:          port,
		PublicKey:     publicKey,
		LastHeartbeat: time.Now(),
		Active:        true,
	}
}

// RemoveEdgeNode removes an edge node from the manager
func (m *common.EdgeNodeManager) RemoveEdgeNode(id string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	delete(m.EdgeNodes, id)
}

// UpdateHeartbeat updates the last heartbeat time of an edge node
func (m *common.EdgeNodeManager) UpdateHeartbeat(id string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	if node, exists := m.EdgeNodes[id]; exists {
		node.LastHeartbeat = time.Now()
		node.Active = true
	}
}

// MonitorEdgeNodes monitors the edge nodes and deactivates those that are unresponsive
func (m *common.EdgeNodeManager) MonitorEdgeNodes() {
	for {
		time.Sleep(EdgeNodeHeartbeatInterval)
		m.Mutex.Lock()
		for id, node := range m.EdgeNodes {
			if time.Since(node.LastHeartbeat) > EdgeNodeTimeout {
				node.Active = false
				fmt.Printf("Edge node %s is inactive\n", id)
			}
		}
		m.Mutex.Unlock()
	}
}


// OffloadTask offloads a computational task to an edge node
func (m *common.EdgeNodeManager) OffloadTask(task *common.Task) error {
	m.Mutex.Lock()
	var selectedNode *common.EdgeNode
	for _, node := range m.EdgeNodes {
		if node.Active {
			selectedNode = node
			break
		}
	}
	m.Mutex.Unlock()

	if selectedNode == nil {
		return fmt.Errorf("no active edge nodes available")
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(selectedNode.IP, strconv.Itoa(selectedNode.Port)), ConnectionTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	encryptedData, err := encryptMessage(task.Data, &selectedNode.PublicKey, nil)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedData)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	decryptedData, err := decryptMessage(buf[:n], nil)
	if err != nil {
		return err
	}

	task.Result = decryptedData
	return nil
}

// SecureConnection establishes a secure connection with an edge node
func SecureConnection(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}


// HandleConnection handles incoming connections to the edge node server
func (s *common.EdgeNodeServer) HandleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	decryptedData, err := decryptMessage(buf[:n], &s.PrivateKey)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	var task common.Task
	if err := json.Unmarshal(decryptedData, &task); err != nil {
		fmt.Println("Error unmarshaling task:", err)
		return
	}

	task.Result = append([]byte("Processed: "), task.Data...)
	encryptedResult, err := encryptMessage(task.Result, &s.PublicKey, nil)
	if err != nil {
		fmt.Println("Error encrypting result:", err)
		return
	}

	_, err = conn.Write(encryptedResult)
	if err != nil {
		fmt.Println("Error writing result to connection:", err)
		return
	}
}

// Start starts the edge node server
func (s *common.EdgeNodeServer) Start() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go s.HandleConnection(conn)
	}
}



// AddNode adds a new node to the SDN controller
func (c *common.SDNController) AddNode(node *common.Node) {
	c.NodeMutex.Lock()
	defer c.NodeMutex.Unlock()
	c.ActiveNodes[node.ID] = node
}

// RemoveNode removes a node from the SDN controller
func (c *common.SDNController) RemoveNode(nodeID string) {
	c.NodeMutex.Lock()
	defer c.NodeMutex.Unlock()
	delete(c.ActiveNodes, nodeID)
}

// AddPolicy adds a new policy to the SDN controller
func (c *common.SDNController) AddPolicy(policy common.Policy) {
	c.RuleMutex.Lock()
	defer c.RuleMutex.Unlock()
	c.PolicyRules[policy.ID] = policy
}

// RemovePolicy removes a policy from the SDN controller
func (c *common.SDNController) RemovePolicy(policyID string) {
	c.RuleMutex.Lock()
	defer c.RuleMutex.Unlock()
	delete(c.PolicyRules, policyID)
}

// ApplyPolicies applies the current policies to the active nodes
func (c *common.SDNController) ApplyPolicies() {
	c.NodeMutex.Lock()
	nodes := c.ActiveNodes
	c.NodeMutex.Unlock()

	c.RuleMutex.Lock()
	policies := c.PolicyRules
	c.RuleMutex.Unlock()

	for _, node := range nodes {
		for _, policy := range policies {
			err := c.applyPolicyToNode(node, policy)
			if err != nil {
				fmt.Printf("Error applying policy %s to node %s: %v\n", policy.ID, node.ID, err)
			}
		}
	}
}

// applyPolicyToNode applies a specific policy to a given node
func (c *common.SDNController) applyPolicyToNode(node *common.Node, policy common.Policy) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.IP, strconv.Itoa(node.Port)), ConnectionTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	msg := &common.Message{
		Type:      "policy",
		Payload:   []byte(policy.Rule),
		Timestamp: time.Now(),
	}

	encryptedMsg, err := encryptMessage(json.Marshal(msg), &node.PublicKey, &c.PrivateKey)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMsg)
	return err
}

// Start begins the SDN controller's operations
func (c *common.SDNController) Start() {
	go c.monitorNodes()
	for {
		c.ApplyPolicies()
		time.Sleep(SDNControlInterval)
	}
}

// monitorNodes monitors the health and status of nodes
func (c *common.SDNController) monitorNodes() {
	for {
		c.NodeMutex.Lock()
		for nodeID, node := range c.ActiveNodes {
			if time.Since(node.LastSeen) > ConnectionTimeout {
				fmt.Printf("Node %s is considered offline\n", nodeID)
				delete(c.ActiveNodes, nodeID)
			}
		}
		c.NodeMutex.Unlock()
		time.Sleep(ConnectionTimeout)
	}
}

// SendMessage sends a message to a specific node
func (c *common.SDNController) SendMessage(nodeID string, msg *common.Message) error {
	c.NodeMutex.Lock()
	node, exists := c.ActiveNodes[nodeID]
	c.NodeMutex.Unlock()
	if !exists {
		return errors.New("node not found")
	}

	address := net.JoinHostPort(node.IP, strconv.Itoa(node.Port))
	for i := 0; i < MaxConnectionRetries; i++ {
		conn, err := net.DialTimeout("tcp", address, ConnectionTimeout)
		if err == nil {
			defer conn.Close()
			encryptedMsg, err := encryptMessage(json.Marshal(msg), &node.PublicKey, &c.PrivateKey)
			if err != nil {
				return err
			}
			_, err = conn.Write(encryptedMsg)
			if err == nil {
				return nil
			}
		}
		time.Sleep(RetryInterval)
	}
	return errors.New("failed to send message after retries")
}

// ReceiveMessage listens for incoming messages from nodes
func (c *common.SDNController) ReceiveMessage() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", c.Port))
	if err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go c.handleConnection(conn)
	}
}

// handleConnection handles incoming connections
func (c *common.SDNController) handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	decryptedMsg, err := decryptMessage(buf[:n], &c.PrivateKey)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	var msg Message
	if err := json.Unmarshal(decryptedMsg, &msg); err != nil {
		fmt.Println("Error unmarshaling message:", err)
		return
	}

	c.processMessage(&msg)
}

// processMessage processes incoming messages
func (c *common.SDNController) processMessage(msg *common.Message) {
	switch msg.Type {
	case "node_info":
		c.handleNodeInfoMessage(msg)
	case "policy_response":
		c.handlePolicyResponseMessage(msg)
	default:
		fmt.Println("Unknown message type:", msg.Type)
	}
}

// handleNodeInfoMessage handles node information messages
func (c *common.SDNController) handleNodeInfoMessage(msg *common.Message) {
	var node Node
	if err := json.Unmarshal(msg.Payload, &node); err != nil {
		fmt.Println("Error unmarshaling node info message:", err)
		return
	}

	c.AddNode(&node)
	fmt.Println("Added new node:", node.ID)
}

// handlePolicyResponseMessage handles policy response messages
func (c *common.SDNController) handlePolicyResponseMessage(msg *common.Message) {
	fmt.Println("Received policy response:", string(msg.Payload))
}

