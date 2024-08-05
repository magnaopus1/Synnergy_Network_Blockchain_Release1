package network

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat"
)

// InitializeBootstrapNode initializes a bootstrap node
func InitializeBootstrapNode(address, port string, maxConnections int, connectionTimeout time.Duration) (BootstrapNode *common.BootstrapNode) {
	return &BootstrapNode{
		Address:          address,
		Port:             port,
		MaxConnections:   maxConnections,
		ConnectionTimeout: connectionTimeout,
	}
}

// Start starts the bootstrap node server to listen for incoming connections
func (bn *common.BootstrapNode) StartBootstrapNode() error {
	listener, err := net.Listen("tcp", net.JoinHostPort(bn.Address, bn.Port))
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logError("Failed to accept connection: ", err)
			continue
		}

		go bn.handleConnection(conn)
	}
}

// handleConnection handles an incoming connection request
func (bn *common.BootstrapNode) HandleConnectionBootstrapNode(conn net.Conn) {
	defer conn.Close()

	if err := bn.authenticateAndValidateNode(conn); err != nil {
		logError("Authentication and validation failed: ", err)
		return
	}

	peerInfo := bn.getPeerInfo(conn)
	bn.addPeer(peerInfo)

	peerList, err := bn.getPeerList()
	if err != nil {
		logError("Failed to get peer list: ", err)
		return
	}

	if err := bn.sendPeerList(conn, peerList); err != nil {
		logError("Failed to send peer list: ", err)
	}
}

// authenticateAndValidateNode authenticates and validates a connecting node
func (bn *common.BootstrapNode) AuthenticateAndValidateNode(conn net.Conn) error {
	// Read public key from the node
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	publicKey := buf[:n]

	// Validate the public key (e.g., check against known good keys, perform challenge-response, etc.)
	if !validatePublicKey(publicKey) {
		return errors.New("invalid public key")
	}

	// Encrypt and send challenge
	challenge := generateRandomBytes(32)
	encryptedChallenge, err := encryptWithPublicKey(publicKey, challenge)
	if err != nil {
		return err
	}

	if _, err := conn.Write(encryptedChallenge); err != nil {
		return err
	}

	// Read the response
	response := make([]byte, 64)
	n, err = conn.Read(response)
	if err != nil {
		return err
	}

	if !validateChallengeResponse(challenge, response) {
		return errors.New("invalid challenge response")
	}

	return nil
}

// getPeerInfo gets the peer information from the connection
func (bn *common.BootstrapNode) GetPeerInfo(conn net.Conn) *common.PeerInfo {
	// Read peer info
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		logError("Failed to read peer info: ", err)
		return nil
	}

	var peerInfo PeerInfo
	if err := json.Unmarshal(buf[:n], &peerInfo); err != nil {
		logError("Failed to unmarshal peer info: ", err)
		return nil
	}

	return &peerInfo
}

// addPeer adds a new peer to the peer list
func (bn *common.BootstrapNode) AddPeerToPeerList(peerInfo *common.PeerInfo) {
	bn.PeerList.Store(peerInfo.ID, peerInfo)
}

// getPeerList retrieves the list of active peers
func (bn *common.BootstrapNode) GetActivePeerList() ([]PeerInfo *common.PeerInfo, error) {
	var peerList []PeerInfo
	bn.PeerList.Range(func(_, value interface{}) bool {
		peer, ok := value.(*PeerInfo)
		if ok {
			peerList = append(peerList, *peer)
		}
		return true
	})
	return peerList, nil
}

// sendPeerList sends the list of active peers to a connecting node
func (bn *common.BootstrapNode) SendActivePeerList(conn net.Conn, peerList []common.PeerInfo) error {
	data, err := json.Marshal(peerList)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

// PeriodicUpdate updates the peer list periodically
func (bn *common.BootstrapNode) PeriodicUpdatePeerList() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bn.updatePeerList()
	}
}

// updatePeerList updates the list of active peers by polling existing connections
func (bn *common.BootstrapNode) UpdatePeerList() {
	bn.PeerList.Range(func(key, value interface{}) bool {
		peer, ok := value.(*common.PeerInfo)
		if !ok {
			bn.PeerList.Delete(key)
			return true
		}

		if !bn.isPeerActive(peer) {
			bn.PeerList.Delete(key)
		}
		return true
	})
}

// isPeerActive checks if a peer is still active
func (bn *common.BootstrapNode) IsPeerActive(peer *common.PeerInfo) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.Address, peer.Port), bn.ConnectionTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// BroadcastChanges broadcasts updates to the peer list to all connected nodes
func (bn *common.BootstrapNode) BroadcastChangesOfPeerList() {
	bn.PeerList.Range(func(_, value interface{}) bool {
		peer, ok := value.(*PeerInfo)
		if !ok {
			return true
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(peer.Address, peer.Port))
		if err != nil {
			logError("Failed to connect to peer: ", err)
			return true
		}
		defer conn.Close()

		peerList, err := bn.getPeerList()
		if err != nil {
			logError("Failed to get peer list: ", err)
			return true
		}

		if err := bn.sendPeerList(conn, peerList); err != nil {
			logError("Failed to send peer list: ", err)
		}

		return true
	})
}


// NewDiscoveryService initializes the discovery service
func NewPeerDiscoveryService(bootstrapNodes []common.BootstrapNode, maxPeers int, connTimeout time.Duration) *DiscoveryService {
	return &DiscoveryService{
		bootstrapNodes: bootstrapNodes,
		maxPeers:       maxPeers,
		connTimeout:    connTimeout,
	}
}

// Start initializes the peer discovery process
func (ds *common.DiscoveryService) StartDiscoveryProcess() error {
	var wg sync.WaitGroup
	for _, node := range ds.bootstrapNodes {
		wg.Add(1)
		go func(node common.BootstrapNode) {
			defer wg.Done()
			ds.discoverPeers(node)
		}(node)
	}
	wg.Wait()
	return nil
}

// discoverPeers connects to a bootstrap node to discover peers
func (ds *common.DiscoveryService) DiscoverPeers(node common.BootstrapNode) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.Address, node.Port), ds.connTimeout)
	if err != nil {
		logError("Failed to connect to bootstrap node: ", err)
		return
	}
	defer conn.Close()

	peers, err := ds.requestPeers(conn)
	if err != nil {
		logError("Failed to request peers: ", err)
		return
	}

	ds.addPeers(peers)
}

// requestPeers sends a request to a bootstrap node to get the list of peers
func (ds *common.DiscoveryService) RequestPeers(conn net.Conn) ([]common.PeerInfo, error) {
	request := &PeerRequest{
		NodeID: generateNodeID(),
	}

	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var response PeerResponse
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		return nil, err
	}

	return response.Peers, nil
}

// addPeers adds discovered peers to the local peer list
func (ds *common.DiscoveryService) AddPeersToLocalPeerList(peers []common.PeerInfo) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	for _, peer := range peers {
		if _, exists := ds.peers.Load(peer.ID); !exists {
			ds.peers.Store(peer.ID, peer)
			if ds.peersCount() >= ds.maxPeers {
				break
			}
		}
	}
}

// peersCount returns the current number of peers
func (ds *common.DiscoveryService) PeersCount() int {
	count := 0
	ds.peers.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// PeriodicUpdate updates the peer list periodically
func (ds *DiscoveryService) PeriodicUpdatePeerListDiscoveryService(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		ds.updatePeers()
	}
}

// updatePeers updates the list of active peers
func (ds *common.DiscoveryService) UpdatePeersListDiscoverService() {
	ds.peers.Range(func(key, value interface{}) bool {
		peer, ok := value.(PeerInfo)
		if !ok || !ds.isPeerActive(peer) {
			ds.peers.Delete(key)
		}
		return true
	})
}

// isPeerActive checks if a peer is still active
func (ds *common.DiscoveryService) IsPeerActive(peer common.PeerInfo) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.Address, peer.Port), ds.connTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// BroadcastChanges broadcasts updates to the peer list to all connected nodes
func (ds *common.DiscoveryService) BroadcastPeerListChanges() {
	ds.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(PeerInfo)
		if !ok {
			return true
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(peer.Address, peer.Port))
		if err != nil {
			logError("Failed to connect to peer: ", err)
			return true
		}
		defer conn.Close()

		peerList, err := ds.getPeerList()
		if err != nil {
			logError("Failed to get peer list: ", err)
			return true
		}

		if err := ds.sendPeerList(conn, peerList); err != nil {
			logError("Failed to send peer list: ", err)
		}

		return true
	})
}

// getPeerList retrieves the list of active peers
func (ds *common.DiscoveryService) GetPeerList() (PeerInfo []common.PeerInfo, error) {
	var peerList []PeerInfo
	ds.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(PeerInfo)
		if ok {
			peerList = append(peerList, peer)
		}
		return true
	})
	return peerList, nil
}

// sendPeerList sends the list of active peers to a connecting node
func (ds *common.DiscoveryService) SendPeerList(conn net.Conn, peerList []common.PeerInfo) error {
	data, err := json.Marshal(peerList)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}


// NewGeoLocationService initializes the geolocation discovery service
func NewGeoLocationService(bootstrapNodes []common.BootstrapNode, maxPeers int, connTimeout time.Duration) *common.GeoLocationService {
	return &GeoLocationService{
		bootstrapNodes: bootstrapNodes,
		maxPeers:       maxPeers,
		connTimeout:    connTimeout,
	}
}

// Start initializes the geolocation-based peer discovery process
func (gls *common.GeoLocationService) StartGeolocationPeerDiscovery() error {
	var wg sync.WaitGroup
	for _, node := range gls.bootstrapNodes {
		wg.Add(1)
		go func(node common.BootstrapNode) {
			defer wg.Done()
			gls.discoverPeers(node)
		}(node)
	}
	wg.Wait()
	return nil
}

// discoverPeers connects to a bootstrap node to discover peers with geolocation data
func (gls *common.GeoLocationService) DiscoverPeersGeoLocationService(node common.BootstrapNode) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.Address, node.Port), gls.connTimeout)
	if err != nil {
		logError("Failed to connect to bootstrap node: ", err)
		return
	}
	defer conn.Close()

	peers, err := gls.requestPeers(conn)
	if err != nil {
		logError("Failed to request peers: ", err)
		return
	}

	gls.addPeers(peers)
}

// requestPeers sends a request to a bootstrap node to get the list of peers with geolocation data
func (gls *common.GeoLocationService) RequestPeersGeolocationData(conn net.Conn) ([]common.PeerInfo, error) {
	request := &PeerRequest{
		NodeID: generateNodeID(),
	}

	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var response PeerResponse
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		return nil, err
	}

	return response.Peers, nil
}

// addPeers adds discovered peers to the local peer list with geolocation prioritization
func (gls *common.GeoLocationService) AddPeersGeoLocationService(peers []common.PeerInfo) {
	gls.mutex.Lock()
	defer gls.mutex.Unlock()

	for _, peer := range peers {
		if _, exists := gls.peers.Load(peer.ID); !exists {
			gls.peers.Store(peer.ID, peer)
			if gls.peersCount() >= gls.maxPeers {
				break
			}
		}
	}
}

// peersCount returns the current number of peers
func (gls *common.GeoLocationService) PeersCountGeolocationService() int {
	count := 0
	gls.peers.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// PeriodicUpdate updates the peer list periodically with geolocation data
func (gls *common.GeoLocationService) PeriodicUpdateGeolocationService(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		gls.updatePeers()
	}
}

// updatePeers updates the list of active peers by polling existing connections and geolocation data
func (gls *common.GeoLocationService) UpdatePeersGeoLocationService() {
	gls.peers.Range(func(key, value interface{}) bool {
		peer, ok := value.(common.PeerInfo)
		if !ok || !gls.isPeerActive(peer) {
			gls.peers.Delete(key)
		}
		return true
	})
}

// isPeerActive checks if a peer is still active
func (gls *common.GeoLocationService) IsPeerActiveGeoLocationService(peer common.PeerInfo) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.Address, peer.Port), gls.connTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// BroadcastChanges broadcasts updates to the peer list to all connected nodes
func (gls *common.GeoLocationService) BroadcastChangesGeoLocationService() {
	gls.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(common.PeerInfo)
		if !ok {
			return true
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(peer.Address, peer.Port))
		if err != nil {
			logError("Failed to connect to peer: ", err)
			return true
		}
		defer conn.Close()

		peerList, err := gls.getPeerList()
		if err != nil {
			logError("Failed to get peer list: ", err)
			return true
		}

		if err := gls.sendPeerList(conn, peerList); err != nil {
			logError("Failed to send peer list: ", err)
		}

		return true
	})
}

// getPeerList retrieves the list of active peers
func (gls *common.GeoLocationService) GetPeerListGeoLocationService() ([]common.PeerInfo, error) {
	var peerList []PeerInfo
	gls.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(common.PeerInfo)
		if ok {
			peerList = append(peerList, peer)
		}
		return true
	})
	return peerList, nil
}

// sendPeerList sends the list of active peers to a connecting node
func (gls *common.GeoLocationService) SendPeerListGeoLocationService(conn net.Conn, peerList []common.PeerInfo) error {
	data, err := json.Marshal(peerList)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

// getDistance calculates the geographical distance between two points using the Haversine formula
func GetGeoLocationServicDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Radius of the Earth in kilometers
	lat1Rad := lat1 * math.Pi / 180
	lon1Rad := lon1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	lon2Rad := lon2 * math.Pi / 180

	dlat := lat2Rad - lat1Rad
	dlon := lon2Rad - lon1Rad

	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

// getGeoLocation retrieves geolocation data for a given IP address
func GetGeoLocationOfIP(ip string) (float64, float64, error) {
	geoData, err := lookupIP(ip)
	if err != nil {
		return 0, 0, err
	}
	return geoData.Latitude, geoData.Longitude, nil
}



// NewKademlia initializes the Kademlia DHT
func NewKademlia(nodeID, address string, connTimeout time.Duration) *common.Kademlia {
	k := &Kademlia{
		NodeID:      nodeID,
		Address:     address,
		connTimeout: connTimeout,
		refreshTimer: time.NewTicker(Expire),
	}
	go k.refreshBuckets()
	return k
}

// FindNode searches for the closest nodes to a given ID
func (k *common.Kademlia) KademliaFindNode(targetID string) ([]*common.Contact, error) {
	closest := k.closestContacts(targetID, Alpha)
	for _, contact := range closest {
		contacts, err := k.sendFindNode(contact, targetID)
		if err != nil {
			logError("Failed to find node: ", err)
			continue
		}
		for _, c := range contacts {
			k.updateContact(c)
		}
	}
	return k.closestContacts(targetID, K), nil
}

// Store places a value in the DHT
func (k *common.Kademlia) StoreInDHT(key, value string) error {
	contacts := k.closestContacts(key, Alpha)
	for _, contact := range contacts {
		err := k.sendStore(contact, key, value)
		if err != nil {
			logError("Failed to store value: ", err)
			return err
		}
	}
	return nil
}

// Get retrieves a value from the DHT
func (k *common.Kademlia) GetValueFromDHT(key string) (string, error) {
	contacts := k.closestContacts(key, Alpha)
	for _, contact := range contacts {
		value, err := k.sendGet(contact, key)
		if err == nil {
			return value, nil
		}
	}
	return "", errors.New("value not found")
}

// AddContact adds a contact to the routing table
func (k *common.Kademlia) AddContactToRoutingTable(contact *common.Contact) {
	k.updateContact(contact)
}

// UpdateContact updates a contact's last seen time
func (k *common.Kademlia) KademliaUpdateContact(contact *common.Contact) {
	k.updateContact(contact)
}

func (k *common.Kademlia) RefreshBuckets() {
	for range k.refreshTimer.C {
		for i := 0; i < len(k.Buckets); i++ {
			if len(k.Buckets[i]) > 0 {
				k.Ping(k.Buckets[i][0].Address)
			}
		}
	}
}

// closestContacts finds the closest contacts to the given ID
func (k *common.Kademlia) ClosestContactsToID(targetID string, count int) []*common.Contact {
	contacts := &ContactHeap{}
	heap.Init(contacts)
	for _, bucket := range k.Buckets {
		for _, contact := range bucket {
			heap.Push(contacts, contact)
		}
		if contacts.Len() >= count {
			break
		}
	}
	result := []*common.Contact{}
	for i := 0; i < count && contacts.Len() > 0; i++ {
		result = append(result, heap.Pop(contacts).(*common.Contact))
	}
	return result
}

// updateContact adds or updates a contact in the routing table
func (k *common.Kademlia) UpdateContactInRoutingTable(contact *common.Contact) {
	bucketIndex := k.bucketIndex(contact.ID)
	k.mutex.Lock()
	defer k.mutex.Unlock()
	bucket := k.Buckets[bucketIndex]
	for i, c := range bucket {
		if c.ID == contact.ID {
			k.Buckets[bucketIndex][i].LastSeen = time.Now()
			return
		}
	}
	if len(bucket) < K {
		k.Buckets[bucketIndex] = append(k.Buckets[bucketIndex], contact)
	} else {
		k.Buckets[bucketIndex][0] = contact
	}
}

// bucketIndex returns the index of the bucket for the given ID
func (k *common.Kademlia) BucketIndex(id string) int {
	nodeIDInt := new(big.Int).SetBytes([]byte(k.NodeID))
	idInt := new(big.Int).SetBytes([]byte(id))
	xor := new(big.Int).Xor(nodeIDInt, idInt)
	return len(xor.Bytes()) * 8
}

// sendFindNode sends a FIND_NODE request to the given contact
func (k *common.Kademlia) SendFindNode(contact *common.Contact, targetID string) ([]*common.Contact, error) {
	conn, err := net.DialTimeout("tcp", contact.Address, k.connTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	request := &common.Message{
		Type:     "FIND_NODE",
		NodeID:   k.NodeID,
		TargetID: targetID,
	}
	err = sendMessage(conn, request)
	if err != nil {
		return nil, err
	}
	response := &common.Message{}
	err = receiveMessage(conn, response)
	if err != nil {
		return nil, err
	}
	if response.Type != "FIND_NODE_RESPONSE" {
		return nil, errors.New("invalid response type")
	}
	return response.Contacts, nil
}

// sendStore sends a STORE request to the given contact
func (k *common.Kademlia) SendStore(contact *common.Contact, key, value string) error {
	conn, err := net.DialTimeout("tcp", contact.Address, k.connTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	request := &common.Message{
		Type:  "STORE",
		NodeID: k.NodeID,
		Key:    key,
		Value:  value,
	}
	return sendMessage(conn, request)
}

// sendGet sends a GET request to the given contact
func (k *common.Kademlia) SendGet(contact *common.Contact, key string) (string, error) {
	conn, err := net.DialTimeout("tcp", contact.Address, k.connTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	request := &common.Message{
		Type:  "GET",
		NodeID: k.NodeID,
		Key:    key,
	}
	err = sendMessage(conn, request)
	if err != nil {
		return "", err
	}
	response := &common.Message{}
	err = receiveMessage(conn, response)
	if err != nil {
		return "", err
	}
	if response.Type != "GET_RESPONSE" {
		return "", errors.New("invalid response type")
	}
	return response.Value, nil
}

// Ping sends a PING request to a contact to check if it's alive
func (k *common.Kademlia) Ping(address string) bool {
	conn, err := net.DialTimeout("tcp", address, k.connTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	request := &common.Message{
		Type:   "PING",
		NodeID: k.NodeID,
	}
	err = sendMessage(conn, request)
	if err != nil {
		return false
	}
	response := &common.Message{}
	err = receiveMessage(conn, response)
	if err != nil {
		return false
	}
	return response.Type == "PONG"
}

// Message represents a Kademlia protocol message
type Message struct {
	Type     string      `json:"type"`
	NodeID   string      `json:"node_id"`
	TargetID string      `json:"target_id,omitempty"`
	Key      string      `json:"key,omitempty"`
	Value    string      `json:"value,omitempty"`
	Contacts []*common.Contact  `json:"contacts,omitempty"`
}

// ContactHeap is a min-heap of contacts based on their distance to a target ID
type ContactHeap []*common.Contact

func (h ContactHeap) Len() int           { return len(h) }
func (h ContactHeap) Less(i, j int) bool { return h[i].LastSeen.Before(h[j].LastSeen) }
func (h ContactHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *ContactHeap) Push(x interface{}) {
	*h = append(*h, x.(*Contact))
}

func (h *ContactHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// GenerateNodeID generates a unique node ID using a hash function
func generateNodeID() string {
	hasher := sha256.New()
	salt := make([]byte, 8)
	_, err := scrypt.Key([]byte(time.Now().String()), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	hasher.Write(salt)
	return hex.EncodeToString(hasher.Sum(nil))
}



// Start initializes the peer discovery process
func (mls *common.MLDiscoveryService) Start() error {
	var wg sync.WaitGroup
	for _, node := range mls.bootstrapNodes {
		wg.Add(1)
		go func(node BootstrapNode) {
			defer wg.Done()
			mls.discoverPeers(node)
		}(node)
	}
	wg.Wait()
	return nil
}

// discoverPeers connects to a bootstrap node to discover peers
func (mls *common.MLDiscoveryService) DiscoverPeers(node common.BootstrapNode) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.Address, node.Port), mls.connTimeout)
	if err != nil {
		logError("Failed to connect to bootstrap node: ", err)
		return
	}
	defer conn.Close()

	peers, err := mls.requestPeers(conn)
	if err != nil {
		logError("Failed to request peers: ", err)
		return
	}

	mls.addPeers(peers)
}

// requestPeers sends a request to a bootstrap node to get the list of peers
func (mls *common.MLDiscoveryService) RequestPeers(conn net.Conn) ([]common.PeerInfo, error) {
	request := &PeerRequest{
		NodeID: generateNodeID(),
	}

	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var response PeerResponse
	err = json.Unmarshal(buf[:n], &response)
	if err != nil {
		return nil, err
	}

	return response.Peers, nil
}

// addPeers adds discovered peers to the local peer list
func (mls *common.MLDiscoveryService) AddPeers(peers []common.PeerInfo) {
	mls.mutex.Lock()
	defer mls.mutex.Unlock()

	for _, peer := range peers {
		if _, exists := mls.peers.Load(peer.ID); !exists {
			mls.peers.Store(peer.ID, peer)
			if mls.peersCount() >= mls.maxPeers {
				break
			}
		}
	}
}

// peersCount returns the current number of peers
func (mls *common.MLDiscoveryService) PeersCount() int {
	count := 0
	mls.peers.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// PeriodicUpdate updates the peer list periodically
func (mls *common.MLDiscoveryService) PeriodicUpdate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		mls.updatePeers()
	}
}

// updatePeers updates the list of active peers by polling existing connections
func (mls *common.MLDiscoveryService) UpdatePeers() {
	mls.peers.Range(func(key, value interface{}) bool {
		peer, ok := value.(PeerInfo)
		if !ok || !mls.isPeerActive(peer) {
			mls.peers.Delete(key)
		}
		return true
	})
}

// isPeerActive checks if a peer is still active
func (mls *common.MLDiscoveryService) IsPeerActive(peer common.PeerInfo) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer.Address, peer.Port), mls.connTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// BroadcastChanges broadcasts updates to the peer list to all connected nodes
func (mls *common.MLDiscoveryService) BroadcastChanges() {
	mls.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(common.PeerInfo)
		if !ok {
			return true
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(peer.Address, peer.Port))
		if err != nil {
			logError("Failed to connect to peer: ", err)
			return true
		}
		defer conn.Close()

		peerList, err := mls.getPeerList()
		if err != nil {
			logError("Failed to get peer list: ", err)
			return true
		}

		if err := mls.sendPeerList(conn, peerList); err != nil {
			logError("Failed to send peer list: ", err)
		}

		return true
	})
}

// getPeerList retrieves the list of active peers
func (mls *common.MLDiscoveryService) GetPeerList() ([]common.PeerInfo, error) {
	var peerList []PeerInfo
	mls.peers.Range(func(_, value interface{}) bool {
		peer, ok := value.(PeerInfo)
		if ok {
			peerList = append(peerList, peer)
		}
		return true
	})
	return peerList, nil
}

// machine learning sendPeerList sends the list of active peers to a connecting node
func (mls *common.MLDiscoveryService) SendPeerList(conn net.Conn, peerList []PeerInfo) error {
	data, err := json.Marshal(peerList)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}


// PredictPeerPerformance predicts the performance of a peer using the trained model
func (mls *common.MLDiscoveryService) PredictPeerPerformance(peer PeerInfo) (float64, error) {
	features := extractFeatures(peer)
	return dotProduct(mls.model.weights, features), nil
}

// extractFeatures extracts features from peer info for model prediction
func ExtractFeatures(peer common.PeerInfo) []float64 {
	// Implement feature extraction logic
	return []float64{peer.Latency, peer.Uptime, peer.DataRate}
}

// dotProduct calculates the dot product of two vectors
func DotProduct(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}
	var result float64
	for i := range a {
		result += a[i] * b[i]
	}
	return result
}


// PeerRequest represents a peer discovery request
type PeerRequest struct {
	NodeID string `json:"node_id"`
}

// PeerResponse represents a peer discovery response
type PeerResponse struct {
	Peers []common.PeerInfo `json:"peers"`
}


// Start begins the peer advertisement process
func (pas *common.PeerAdvertisementService) Start() {
	go pas.advertise()
}

// Stop halts the peer advertisement process
func (pas *common.PeerAdvertisementService) Stop() {
	close(pas.stopCh)
}

// advertise periodically sends advertisement messages to the network
func (pas *common.PeerAdvertisementService) Advertise() {
	for {
		select {
		case <-pas.advertiseTicker.C:
			advertisement, err := pas.createAdvertisement()
			if err != nil {
				logError("Failed to create advertisement: ", err)
				continue
			}
			pas.broadcastAdvertisement(advertisement)
		case <-pas.stopCh:
			return
		}
	}
}

// createAdvertisement constructs a new advertisement message
func (pas *common.PeerAdvertisementService) CreateAdvertisement() (Advertisement common.Advertisement, error) {
	timestamp := time.Now().Unix()
	message := &Advertisement{
		NodeID:    pas.nodeID,
		Address:   pas.address,
		Port:      pas.port,
		PublicKey: pas.publicKey,
		Timestamp: timestamp,
	}
	signature, err := pas.signMessage(message)
	if err != nil {
		return Advertisement{}, err
	}
	message.Signature = signature
	return *message, nil
}

// signMessage signs the advertisement message
func (pas *common.PeerAdvertisementService) SignMessage(message *common.Advertisement) ([]byte, error) {
	data, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	hashedData := sha3.Sum256(data)
	signature, err := sign(hashedData[:], pas.publicKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// broadcastAdvertisement sends the advertisement to all known peers
func (pas *common.PeerAdvertisementService) BroadcastAdvertisement(advertisement common.Advertisement) {
	data, err := json.Marshal(advertisement)
	if err != nil {
		logError("Failed to marshal advertisement: ", err)
		return
	}
	pas.peers.Range(func(key, value interface{}) bool {
		peerAddress := value.(string)
		conn, err := net.Dial("tcp", peerAddress)
		if err != nil {
			logError("Failed to connect to peer: ", err)
			return true
		}
		defer conn.Close()
		_, err = conn.Write(data)
		if err != nil {
			logError("Failed to send advertisement to peer: ", err)
		}
		return true
	})
}

// HandleIncomingAdvertisements handles incoming advertisement messages from peers
func (pas *common.PeerAdvertisementService) HandleIncomingAdvertisements(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		logError("Failed to read from connection: ", err)
		return
	}
	var advertisement common.Advertisement
	err = json.Unmarshal(buf[:n], &advertisement)
	if err != nil {
		logError("Failed to unmarshal advertisement: ", err)
		return
	}
	if err := pas.validateAdvertisement(&advertisement); err != nil {
		logError("Invalid advertisement: ", err)
		return
	}
	pas.updatePeerList(advertisement)
}

// validateAdvertisement checks the authenticity and integrity of the received advertisement
func (pas *common.PeerAdvertisementService) ValidateAdvertisement(advertisement *common.Advertisement) error {
	// Check timestamp
	if time.Now().Unix()-advertisement.Timestamp > 600 {
		return errors.New("advertisement timestamp is too old")
	}
	// Verify signature
	data, err := json.Marshal(advertisement)
	if err != nil {
		return err
	}
	hashedData := sha3.Sum256(data)
	if !verifySignature(advertisement.PublicKey, hashedData[:], advertisement.Signature) {
		return errors.New("invalid advertisement signature")
	}
	return nil
}

// updatePeerList adds or updates the peer information in the local peer list
func (pas *common.PeerAdvertisementService) UpdatePeerList(advertisement common.Advertisement) {
	pas.peers.Store(advertisement.NodeID, net.JoinHostPort(advertisement.Address, advertisement.Port))
}

type AdvertisementRequest struct {
	NodeID string `json:"node_id"`
}

// HandleAdvertisementRequest processes incoming advertisement requests
func (pas *common.PeerAdvertisementService) HandleAdvertisementRequest(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		logError("Failed to read from connection: ", err)
		return
	}
	var request AdvertisementRequest
	err = json.Unmarshal(buf[:n], &request)
	if err != nil {
		logError("Failed to unmarshal advertisement request: ", err)
		return
	}
	advertisement, err := pas.createAdvertisement()
	if err != nil {
		logError("Failed to create advertisement: ", err)
		return
	}
	data, err := json.Marshal(advertisement)
	if err != nil {
		logError("Failed to marshal advertisement: ", err)
		return
	}
	_, err = conn.Write(data)
	if err != nil {
		logError("Failed to send advertisement: ", err)
	}
}










