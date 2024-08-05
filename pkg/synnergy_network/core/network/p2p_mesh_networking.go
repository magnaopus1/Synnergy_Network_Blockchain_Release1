package network

import (
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)



// UpdateMetrics updates the link quality metrics for a given node
func (nlm *common.NodeLinkMetrics) UpdateMetrics(nodeID string, latency time.Duration, bandwidth, packetLoss, jitter float64) {
	nlm.mutex.Lock()
	defer nlm.mutex.Unlock()
	nlm.metrics[nodeID] = &common.LinkQualityMetrics{
		Latency:     latency,
		Bandwidth:   bandwidth,
		PacketLoss:  packetLoss,
		Jitter:      jitter,
		LastUpdated: time.Now(),
	}
}

// GetMetrics retrieves the link quality metrics for a given node
func (nlm *common.NodeLinkMetrics) GetMetrics(nodeID string) (*common.LinkQualityMetrics, error) {
	nlm.mutex.Lock()
	defer nlm.mutex.Unlock()
	metrics, exists := nlm.metrics[nodeID]
	if !exists {
		return nil, errors.New("no metrics found for the given node ID")
	}
	return metrics, nil
}

// AdaptiveLinkQualityService manages adaptive link quality metrics
type AdaptiveLinkQualityService struct {
	nodeID          string
	nodeLinkMetrics *common.NodeLinkMetrics
	metricUpdateCh  chan string
	stopCh          chan struct{}
}

// NewAdaptiveLinkQualityService initializes a new AdaptiveLinkQualityService instance
func NewAdaptiveLinkQualityService(nodeID string) (AdaptiveLinkQualityService *common.AdaptiveLinkQualityService) {
	return &AdaptiveLinkQualityService{
		nodeID:          nodeID,
		nodeLinkMetrics: NewNodeLinkMetrics(),
		metricUpdateCh:  make(chan string),
		stopCh:          make(chan struct{}),
	}
}

// Start begins the adaptive link quality service
func (alq *commonAdaptiveLinkQualityService) Start() {
	go alq.monitorLinkQuality()
}

// Stop halts the adaptive link quality service
func (alq *commonAdaptiveLinkQualityService) Stop() {
	close(alq.stopCh)
}

// monitorLinkQuality continuously monitors and updates link quality metrics
func (alq *commonAdaptiveLinkQualityService) MonitorLinkQuality() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			alq.updateAllMetrics()
		case <-alq.stopCh:
			return
		}
	}
}

// updateAllMetrics updates the link quality metrics for all known nodes
func (alq *commonAdaptiveLinkQualityService) UpdateAllMetrics() {
	alq.nodeLinkMetrics.mutex.Lock()
	defer alq.nodeLinkMetrics.mutex.Unlock()
	for nodeID := range alq.nodeLinkMetrics.metrics {
		latency, bandwidth, packetLoss, jitter, err := alq.measureLinkQuality(nodeID)
		if err != nil {
			log.Printf("Failed to measure link quality: %v", err)
			continue
		}
		alq.nodeLinkMetrics.UpdateMetrics(nodeID, latency, bandwidth, packetLoss, jitter)
	}
}

// measureLinkQuality measures the link quality metrics for a given node
func (alq *commonAdaptiveLinkQualityService) MeasureLinkQuality(nodeID string) (time.Duration, float64, float64, float64, error) {
	// Dummy implementation for measurement; replace with real measurement logic
	latency := time.Duration(math.Round(float64(time.Millisecond * 50)))
	bandwidth := 100.0  // Mbps
	packetLoss := 0.01  // 1%
	jitter := 5.0       // ms
	return latency, bandwidth, packetLoss, jitter, nil
}

// EncryptData encrypts data using the best available method for the situation (scrypt or argon2)
func EncryptData(data []byte, method string) ([]byte, error) {
	var encryptedData []byte
	var err error
	switch method {
	case "scrypt":
		salt := make([]byte, 16)
		_, err := cryptoRandRead(salt)
		if err != nil {
			return nil, err
		}
		encryptedData, err = scrypt.Key(data, salt, 1<<15, 8, 1, 32)
	case "argon2":
		salt := make([]byte, 16)
		_, err := cryptoRandRead(salt)
		if err != nil {
			return nil, err
		}
		encryptedData = argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
	default:
		return nil, errors.New("unsupported encryption method")
	}
	return encryptedData, err
}

// CalculateLinkQualityScore calculates a score based on link quality metrics
func (alq *commonAdaptiveLinkQualityService) CalculateLinkQualityScore(nodeID string) (float64, error) {
	metrics, err := alq.nodeLinkMetrics.GetMetrics(nodeID)
	if err != nil {
		return 0, err
	}
	score := 100.0 - (metrics.Latency.Seconds()*10 + metrics.PacketLoss*50 + metrics.Jitter*5)
	if metrics.Bandwidth < 50 {
		score -= (50 - metrics.Bandwidth)
	}
	return score, nil
}


// UpdateRoute updates the routing information for a given node
func (nrt *commonNodeRoutingTable) UpdateRoute(nodeID, address string) {
	nrt.mutex.Lock()
	defer nrt.mutex.Unlock()
	nrt.routes[nodeID] = address
	nrt.lastSeen[nodeID] = time.Now()
}

// GetRoute retrieves the address for a given node
func (nrt *commonNodeRoutingTable) GetRoute(nodeID string) (string, error) {
	nrt.mutex.Lock()
	defer nrt.mutex.Unlock()
	address, exists := nrt.routes[nodeID]
	if !exists {
		return "", errors.New("no route found for the given node ID")
	}
	return address, nil
}

// CleanupRoutes removes stale routes that have not been updated recently
func (nrt *commonNodeRoutingTable) CleanupRoutes(timeout time.Duration) {
	nrt.mutex.Lock()
	defer nrt.mutex.Unlock()
	now := time.Now()
	for nodeID, lastSeen := range nrt.lastSeen {
		if now.Sub(lastSeen) > timeout {
			delete(nrt.routes, nodeID)
			delete(nrt.lastSeen, nodeID)
			log.Printf("Removed stale route for node %s", nodeID)
		}
	}
}



// NewBlockchainBackedRoutingService creates a new BlockchainBackedRoutingService instance
func NewBlockchainBackedRoutingService(nodeID string) *BlockchainBackedRoutingService {
	return &BlockchainBackedRoutingService{
		nodeID:          nodeID,
		routingTable:    NewNodeRoutingTable(),
		advertisementCh: make(chan common.RoutingAdvertisement),
		stopCh:          make(chan struct{}),
	}
}

// Start begins the blockchain-backed routing service
func (bbr *common.BlockchainBackedRoutingService) Start() {
	go bbr.advertise()
	go bbr.listenForAdvertisements()
}

// Stop halts the blockchain-backed routing service
func (bbr *common.BlockchainBackedRoutingService) Stop() {
	close(bbr.stopCh)
}

// advertise periodically sends routing advertisements to the network
func (bbr *common.BlockchainBackedRoutingService) Advertise() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			advertisement, err := bbr.createAdvertisement()
			if err != nil {
				log.Printf("Failed to create advertisement: %v", err)
				continue
			}
			bbr.broadcastAdvertisement(advertisement)
		case <-bbr.stopCh:
			return
		}
	}
}

// createAdvertisement constructs a new routing advertisement message
func (bbr *common.BlockchainBackedRoutingService) CreateAdvertisement() (RoutingAdvertisment common.RoutingAdvertisement, error) {
	timestamp := time.Now().Unix()
	message := &RoutingAdvertisement{
		NodeID:    bbr.nodeID,
		Address:   bbr.routingTable.routes[bbr.nodeID],
		Timestamp: timestamp,
	}
	signature, err := bbr.signMessage(message)
	if err != nil {
		return RoutingAdvertisement{}, err
	}
	message.Signature = signature
	return *message, nil
}

// signMessage signs the routing advertisement message
func (bbr *common.BlockchainBackedRoutingService) SignMessage(message *common.RoutingAdvertisement) ([]byte, error) {
	data, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	hashedData := hashSHA3(data)
	signature, err := sign(hashedData, bbr.nodeID)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// broadcastAdvertisement sends the advertisement to all known peers
func (bbr *common.BlockchainBackedRoutingService) BroadcastAdvertisement(advertisement common.RoutingAdvertisement) {
	data, err := json.Marshal(advertisement)
	if err != nil {
		log.Printf("Failed to marshal advertisement: %v", err)
		return
	}
	bbr.routingTable.mutex.Lock()
	defer bbr.routingTable.mutex.Unlock()
	for nodeID, address := range bbr.routingTable.routes {
		if nodeID == bbr.nodeID {
			continue
		}
		conn, err := net.Dial("tcp", address)
		if err != nil {
			log.Printf("Failed to connect to peer: %v", err)
			continue
		}
		defer conn.Close()
		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Failed to send advertisement to peer: %v", err)
		}
	}
}

// listenForAdvertisements listens for incoming routing advertisements
func (bbr *common.BlockchainBackedRoutingService) ListenForAdvertisements() {
	listener, err := net.Listen("tcp", bbr.routingTable.routes[bbr.nodeID])
	if err != nil {
		log.Printf("Failed to start listener: %v", err)
		return
	}
	defer listener.Close()
	for {
		select {
		case <-bbr.stopCh:
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			go bbr.handleIncomingAdvertisement(conn)
		}
	}
}

// handleIncomingAdvertisement processes incoming routing advertisement messages
func (bbr *common.BlockchainBackedRoutingService) HandleIncomingAdvertisement(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		return
	}
	var advertisement common.RoutingAdvertisement
	err = json.Unmarshal(buf[:n], &advertisement)
	if err != nil {
		log.Printf("Failed to unmarshal advertisement: %v", err)
		return
	}
	if err := bbr.validateAdvertisement(&advertisement); err != nil {
		log.Printf("Invalid advertisement: %v", err)
		return
	}
	bbr.routingTable.UpdateRoute(advertisement.NodeID, advertisement.Address)
}

// validateAdvertisement checks the authenticity and integrity of the received advertisement
func (bbr *common.BlockchainBackedRoutingService) ValidateAdvertisement(advertisement *common.RoutingAdvertisement) error {
	// Check timestamp
	if time.Now().Unix()-advertisement.Timestamp > 600 {
		return errors.New("advertisement timestamp is too old")
	}
	// Verify signature
	data, err := json.Marshal(advertisement)
	if err != nil {
		return err
	}
	hashedData := hashSHA3(data)
	if !verifySignature(advertisement.NodeID, hashedData, advertisement.Signature) {
		return errors.New("invalid advertisement signature")
	}
	return nil
}

// CleanupStaleRoutes periodically cleans up stale routes in the routing table
func (bbr *common.BlockchainBackedRoutingService) CleanupStaleRoutes(timeout time.Duration) {
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			bbr.routingTable.CleanupRoutes(timeout)
		case <-bbr.stopCh:
			return
		}
	}
}

// Constants for managing routing table
const (
	RoutingTableRefreshInterval = 30 * time.Second
	NodeExpirationTime          = 5 * time.Minute
)

// NewRoutingTable creates a new instance of RoutingTable
func NewRoutingTable() (RoutingTable *common.RoutingTable) {
	return &RoutingTable{
		nodes: make(map[string]*common.Node),
	}
}

// AddNode adds a new node to the routing table
func (rt *common.RoutingTable) AddNode(node *common.Node) {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	rt.nodes[node.ID] = node
}

// RemoveNode removes a node from the routing table
func (rt *common.RoutingTable) RemoveNode(nodeID string) {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	delete(rt.nodes, nodeID)
}

// GetNode retrieves a node from the routing table
func (rt *common.RoutingTable) GetNode(nodeID string) (*common.Node, error) {
	rt.lock.RLock()
	defer rt.lock.RUnlock()
	node, exists := rt.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// Refresh refreshes the routing table, removing expired nodes
func (rt *common.RoutingTable) Refresh() {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	for id, node := range rt.nodes {
		if time.Since(node.LastSeen) > NodeExpirationTime {
			delete(rt.nodes, id)
		}
	}
}


// Start begins the node discovery process and routing table maintenance
func (nds *commonNodeDiscoveryService) Start() {
	go nds.discoveryLoop()
	go nds.refreshLoop()
}

// discoveryLoop continuously discovers new nodes and adds them to the routing table
func (nds *NodeDiscoveryService) DiscoveryLoop() {
	for {
		newNodes := discoverPeers()
		for _, node := range newNodes {
			nds.routingTable.AddNode(node)
		}
		time.Sleep(RoutingTableRefreshInterval)
	}
}

// refreshLoop periodically refreshes the routing table
func (nds *NodeDiscoveryService) RefreshLoop() {
	for {
		nds.routingTable.Refresh()
		time.Sleep(RoutingTableRefreshInterval)
	}
}

// SendMessage sends a message to a specified node
func (nds *NodeDiscoveryService) SendMessage(nodeID string, message []byte) error {
	node, err := nds.routingTable.GetNode(nodeID)
	if err != nil {
		return err
	}

	encryptedMessage, err := encrypt(message, node.PublicKey)
	if err != nil {
		return err
	}

	return send(node.Address, encryptedMessage)
}

// ReceiveMessage handles incoming messages
func (nds *NodeDiscoveryService) ReceiveMessage() {
	for {
		msg, addr, err := receive()
		if err != nil {
			continue
		}

		nodeID := hashAddress(addr)
		node, err := nds.routingTable.GetNode(nodeID)
		if err != nil {
			// Handle unknown node (e.g., add to routing table after verification)
			continue
		}

		decryptedMessage, err := decrypt(msg, node.PublicKey)
		if err != nil {
			continue
		}

		// Process the message
		_ = processIncomingMessage(decryptedMessage)
	}
}

// processIncomingMessage processes an incoming message
func ProcessIncomingMessage(message []byte) error {
	// Implement message processing logic
	return nil
}

// Constants for managing dynamic network formation
const (
	BootstrapNodeAddress     = "bootstrap.synnergy.network:8080"
	PeerDiscoveryInterval    = 30 * time.Second
	PeerCheckInterval        = 5 * time.Minute
	MaxPeers                 = 50
	AdaptiveMetricsInterval  = 10 * time.Second
)


// Start begins the dynamic network formation and peer discovery process
func (nm *common.NetworkManager) Start() {
	go nm.peerDiscoveryLoop()
	go nm.peerCheckLoop()
	go nm.adaptiveMetricsLoop()
}

// peerDiscoveryLoop continuously discovers new peers
func (nm *common.NetworkManager) PeerDiscoveryLoop() {
	for {
		newPeers := discoverPeers(nm.localNode.ID, nm.bootstrapNodes)
		for _, peer := range newPeers {
			nm.addPeer(peer)
		}
		time.Sleep(PeerDiscoveryInterval)
	}
}

// peerCheckLoop periodically checks and updates the status of peers
func (nm *common.NetworkManager) PeerCheckLoop() {
	for {
		nm.lock.Lock()
		for id, peer := range nm.peers {
			if time.Since(peer.LastSeen) > PeerCheckInterval {
				delete(nm.peers, id)
			}
		}
		nm.lock.Unlock()
		time.Sleep(PeerCheckInterval)
	}
}

// adaptiveMetricsLoop periodically updates link quality metrics for peers
func (nm *common.NetworkManager) AdaptiveMetricsLoop() {
	for {
		nm.lock.RLock()
		for _, peer := range nm.peers {
			go nm.updateLinkQuality(peer)
		}
		nm.lock.RUnlock()
		time.Sleep(AdaptiveMetricsInterval)
	}
}

// addPeer adds a new peer to the network manager
func (nm *common.NetworkManager) AddPeer(peer *common.Node) {
	nm.lock.Lock()
	defer nm.lock.Unlock()
	if len(nm.peers) < MaxPeers {
		nm.peers[peer.ID] = peer
	}
}

// updateLinkQuality updates the link quality metrics for a given peer
func (nm *common.NetworkManager) UpdateLinkQuality(peer *common.Node) {
	// Implement the link quality metrics calculation logic
	// This could include metrics like latency, throughput, and error rates
	latency := nm.measureLatency(peer)
	throughput := nm.measureThroughput(peer)
	errorRate := nm.measureErrorRate(peer)

	// Update the peer with new metrics
	peer.LinkQuality = calculateLinkQuality(latency, throughput, errorRate)
}

// measureLatency measures the latency to a given peer
func (nm *common.NetworkManager) MeasureLatency(peer *common.Node) time.Duration {
	start := time.Now()
	conn, err := net.Dial("tcp", peer.Address)
	if err != nil {
		return time.Duration(0)
	}
	conn.Close()
	return time.Since(start)
}

// measureThroughput measures the throughput to a given peer
func (nm *common.NetworkManager) MeasureThroughput(peer *common.Node) float64 {
	// Implement the throughput measurement logic
	// This is a placeholder implementation
	return 100.0 // Mbps
}

// measureErrorRate measures the error rate to a given peer
func (nm *common.NetworkManager) MeasureErrorRate(peer *common.Node) float64 {
	// Implement the error rate measurement logic
	// This is a placeholder implementation
	return 0.01 // 1%
}

// calculateLinkQuality calculates the overall link quality based on metrics
func CalculateLinkQuality(latency time.Duration, throughput float64, errorRate float64) float64 {
	// Implement the link quality calculation logic
	// This is a placeholder implementation
	return 100.0 - (latency.Seconds()*10 + errorRate*100)
}

// SendMessage sends a message to a specified peer
func (nm *common.NetworkManager) SendMessage(peerID string, message []byte) error {
	peer, err := nm.getPeer(peerID)
	if err != nil {
		return err
	}

	encryptedMessage, err := encrypt(message, peer.PublicKey)
	if err != nil {
		return err
	}

	return send(peer.Address, encryptedMessage)
}

// ReceiveMessage handles incoming messages
func (nm *common.NetworkManager) ReceiveMessage() {
	for {
		msg, addr, err := receive()
		if err != nil {
			continue
		}

		nodeID := hashAddress(addr)
		peer, err := nm.getPeer(nodeID)
		if err != nil {
			// Handle unknown peer (e.g., add to peers after verification)
			continue
		}

		decryptedMessage, err := decrypt(msg, peer.PublicKey)
		if err != nil {
			continue
		}

		// Process the message
		_ = processIncomingMessage(decryptedMessage)
	}
}

// getPeer retrieves a peer from the network manager
func (nm *common.NetworkManager) GetPeer(peerID string) (*Node, error) {
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	peer, exists := nm.peers[peerID]
	if !exists {
		return nil, errors.New("peer not found")
	}
	return peer, nil
}

// Start begins the mesh network formation and maintenance process
func (mn *common.MeshNetwork) Start() {
	go mn.peerDiscoveryLoop()
	go mn.heartbeatLoop()
	go mn.refreshLoop()
}

// peerDiscoveryLoop continuously discovers new peers and adds them to the mesh network
func (mn *common.MeshNetwork) peerDiscoveryLoop() {
	for {
		newPeers := discoverPeers(mn.localNode.ID)
		for _, peer := range newPeers {
			mn.addPeer(peer)
		}
		time.Sleep(MeshNetworkRefreshInterval)
	}
}

// heartbeatLoop periodically sends heartbeat messages to peers to maintain active connections
func (mn *common.MeshNetwork) HeartbeatLoop() {
	for {
		mn.lock.RLock()
		for _, peer := range mn.peers {
			go mn.sendHeartbeat(peer)
		}
		mn.lock.RUnlock()
		time.Sleep(MeshNodeHeartbeatInterval)
	}
}

// refreshLoop periodically refreshes the mesh network, removing expired nodes
func (mn *common.MeshNetwork) RefreshLoop() {
	for {
		mn.lock.Lock()
		for id, peer := range mn.peers {
			if time.Since(peer.LastSeen) > MeshNodeExpirationTime {
				delete(mn.peers, id)
			}
		}
		mn.lock.Unlock()
		time.Sleep(MeshNetworkRefreshInterval)
	}
}

// addPeer adds a new peer to the mesh network
func (mn *common.MeshNetwork) addPeer(peer *common.MeshNode) {
	mn.lock.Lock()
	defer mn.lock.Unlock()
	if len(mn.peers) < MaxMeshPeers {
		mn.peers[peer.ID] = peer
	}
}

// sendHeartbeat sends a heartbeat message to a peer to keep the connection active
func (mn *common.MeshNetwork) sendHeartbeat(peer *common.MeshNode) error {
	heartbeatMessage := []byte("heartbeat")
	encryptedMessage, err := encrypt(heartbeatMessage, peer.PublicKey)
	if err != nil {
		return err
	}
	return send(peer.Address, encryptedMessage)
}

// SendMessage sends a message to a specified peer
func (mn *common.MeshNetwork) SendMessage(peerID string, message []byte) error {
	peer, err := mn.getPeer(peerID)
	if err != nil {
		return err
	}

	encryptedMessage, err := encrypt(message, peer.PublicKey)
	if err != nil {
		return err
	}

	return send(peer.Address, encryptedMessage)
}

// ReceiveMessage handles incoming messages
func (mn *common.MeshNetwork) ReceiveMessage() {
	for {
		msg, addr, err := receive()
		if err != nil {
			continue
		}

		nodeID := hashAddress(addr)
		peer, err := mn.getPeer(nodeID)
		if err != nil {
			// Handle unknown peer (e.g., add to mesh network after verification)
			continue
		}

		decryptedMessage, err := decrypt(msg, peer.PublicKey)
		if err != nil {
			continue
		}

		// Process the message
		_ = processIncomingMessage(decryptedMessage)
	}
}

// getPeer retrieves a peer from the mesh network
func (mn *common.MeshNetwork) getPeer(peerID string) (*common.MeshNode, error) {
	mn.lock.RLock()
	defer mn.lock.RUnlock()
	peer, exists := mn.peers[peerID]
	if !exists {
		return nil, errors.New("peer not found")
	}
	return peer, nil
}


// AddNode adds a new node to the routing table
func (rt *common.MeshRoutingTable) AddNode(node *common.MeshRoutingNode) {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	rt.nodes[node.ID] = node
}

// RemoveNode removes a node from the routing table
func (rt *common.MeshRoutingTable) RemoveNode(nodeID string) {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	delete(rt.nodes, nodeID)
}

// GetNode retrieves a node from the routing table
func (rt *common.MeshRoutingTable) GetNode(nodeID string) (*common.MeshRoutingNode, error) {
	rt.lock.RLock()
	defer rt.lock.RUnlock()
	node, exists := rt.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// Refresh refreshes the routing table, removing expired nodes
func (rt *common.MeshRoutingTable) Refresh() {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	for id, node := range rt.nodes {
		if time.Since(node.LastSeen) > MeshRoutingTableExpiry {
			delete(rt.nodes, id)
		}
	}
}


// Start begins the routing and maintenance process for the mesh network
func (mrs *common.MeshRoutingService) Start() {
	go mrs.peerDiscoveryLoop()
	go mrs.peerHeartbeatLoop()
	go mrs.routingTableRefreshLoop()
}

// peerDiscoveryLoop continuously discovers new peers and adds them to the routing table
func (mrs *common.MeshRoutingService) peerDiscoveryLoop() {
	for {
		newPeers := discoverPeers(mrs.localNode.ID)
		for _, peer := range newPeers {
			mrs.addPeer(peer)
		}
		time.Sleep(PeerDiscoveryInterval)
	}
}

// peerHeartbeatLoop periodically sends heartbeat messages to peers to maintain active connections
func (mrs *common.MeshRoutingService) peerHeartbeatLoop() {
	for {
		mrs.routingTable.lock.RLock()
		for _, peer := range mrs.routingTable.nodes {
			go mrs.sendHeartbeat(peer)
		}
		mrs.routingTable.lock.RUnlock()
		time.Sleep(PeerHeartbeatInterval)
	}
}

// routingTableRefreshLoop periodically refreshes the routing table
func (mrs *common.MeshRoutingService) routingTableRefreshLoop() {
	for {
		mrs.routingTable.Refresh()
		time.Sleep(MeshRoutingInterval)
	}
}

// addPeer adds a new peer to the routing table
func (mrs *common.MeshRoutingService) addPeer(peer *common.MeshRoutingNode) {
	mrs.routingTable.lock.Lock()
	defer mrs.routingTable.lock.Unlock()
	if len(mrs.routingTable.nodes) < MaxRoutingPeers {
		mrs.routingTable.nodes[peer.ID] = peer
	}
}

// sendHeartbeat sends a heartbeat message to a peer to keep the connection active
func (mrs *common.MeshRoutingService) sendHeartbeat(peer *common.MeshRoutingNode) error {
	heartbeatMessage := []byte("heartbeat")
	encryptedMessage, err := encrypt(heartbeatMessage, peer.PublicKey)
	if err != nil {
		return err
	}
	return send(peer.Address, encryptedMessage)
}

// SendMessage sends a message to a specified peer
func (mrs *common.MeshRoutingService) SendMessage(peerID string, message []byte) error {
	peer, err := mrs.routingTable.GetNode(peerID)
	if err != nil {
		return err
	}

	encryptedMessage, err := encrypt(message, peer.PublicKey)
	if err != nil {
		return err
	}

	return send(peer.Address, encryptedMessage)
}

// ReceiveMessage handles incoming messages
func (mrs *common.MeshRoutingService) ReceiveMessage() {
	for {
		msg, addr, err := receive()
		if err != nil {
			continue
		}

		nodeID := hashAddress(addr)
		peer, err := mrs.routingTable.GetNode(nodeID)
		if err != nil {
			// Handle unknown peer (e.g., add to routing table after verification)
			continue
		}

		decryptedMessage, err := decrypt(msg, peer.PublicKey)
		if err != nil {
			continue
		}

		// Process the message
		_ = processIncomingMessage(decryptedMessage)
	}
}


// Start begins the mesh network formation and maintenance process for mobile devices
func (mn *common.MobileMeshNetwork) Start() {
	go mn.peerDiscoveryLoop()
	go mn.heartbeatLoop()
	go mn.refreshLoop()
}

// peerDiscoveryLoop continuously discovers new peers and adds them to the mesh network
func (mn *common.MobileMeshNetwork) peerDiscoveryLoop() {
	for {
		newPeers := discoverPeers(mn.localNode.ID)
		for _, peer := range newPeers {
			mn.addPeer(peer)
		}
		time.Sleep(MobileNetworkRefreshInterval)
	}
}

// heartbeatLoop periodically sends heartbeat messages to peers to maintain active connections
func (mn *common.MobileMeshNetwork) heartbeatLoop() {
	for {
		mn.lock.RLock()
		for _, peer := range mn.peers {
			go mn.sendHeartbeat(peer)
		}
		mn.lock.RUnlock()
		time.Sleep(MobileNodeHeartbeatInterval)
	}
}

// refreshLoop periodically refreshes the mesh network, removing expired nodes
func (mn *common.MobileMeshNetwork) refreshLoop() {
	for {
		mn.lock.Lock()
		for id, peer := range mn.peers {
			if time.Since(peer.LastSeen) > MobileNodeExpirationTime {
				delete(mn.peers, id)
			}
		}
		mn.lock.Unlock()
		time.Sleep(MobileNetworkRefreshInterval)
	}
}

// addPeer adds a new peer to the mesh network
func (mn *common.MobileMeshNetwork) addPeer(peer *common.MobileMeshNode) {
	mn.lock.Lock()
	defer mn.lock.Unlock()
	if len(mn.peers) < MaxMobilePeers {
		mn.peers[peer.ID] = peer
	}
}

// sendHeartbeat sends a heartbeat message to a peer to keep the connection active
func (mn *common.MobileMeshNetwork) sendHeartbeat(peer *common.MobileMeshNode) error {
	heartbeatMessage := []byte("heartbeat")
	encryptedMessage, err := encrypt(heartbeatMessage, peer.PublicKey)
	if err != nil {
		return err
	}
	return send(peer.Address, encryptedMessage)
}

// SendMessage sends a message to a specified peer
func (mn *common.MobileMeshNetwork) SendMessage(peerID string, message []byte) error {
	peer, err := mn.getPeer(peerID)
	if err != nil {
		return err
	}

	encryptedMessage, err := encrypt(message, peer.PublicKey)
	if err != nil {
		return err
	}

	return send(peer.Address, encryptedMessage)
}

// ReceiveMessage handles incoming messages
func (mn *common.MobileMeshNetwork) ReceiveMessage() {
	for {
		msg, addr, err := receive()
		if err != nil {
			continue
		}

		nodeID := hashAddress(addr)
		peer, err := mn.getPeer(nodeID)
		if err != nil {
			// Handle unknown peer (e.g., add to mesh network after verification)
			continue
		}

		decryptedMessage, err := decrypt(msg, peer.PublicKey)
		if err != nil {
			continue
		}

		// Process the message
		_ = processIncomingMessage(decryptedMessage)
	}
}

// getPeer retrieves a peer from the mesh network
func (mn *common.MobileMeshNetwork) getPeer(peerID string) (*common.MobileMeshNode, error) {
	mn.lock.RLock()
	defer mn.lock.RUnlock()
	peer, exists := mn.peers[peerID]
	if !exists {
		return nil, errors.New("peer not found")
	}
	return peer, nil
}


