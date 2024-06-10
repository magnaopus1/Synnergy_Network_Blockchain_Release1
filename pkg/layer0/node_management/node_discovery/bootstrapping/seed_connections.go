package bootstrapping

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// SeedNode represents a seed node in the blockchain network.
type SeedNode struct {
	ID        string
	Address   string
	PublicKey *rsa.PublicKey
}

// BootstrapManager manages the bootstrapping of new nodes into the network.
type BootstrapManager struct {
	mu               sync.Mutex
	seedNodes        []SeedNode
	connectedNodes   map[string]*Node
	dht              *DHT
	httpClient       *http.Client
	connectionTimeout time.Duration
}

// NewBootstrapManager creates a new BootstrapManager.
func NewBootstrapManager(seedNodeAddresses []string, connectionTimeout time.Duration) (*BootstrapManager, error) {
	seedNodes := make([]SeedNode, len(seedNodeAddresses))
	for i, address := range seedNodeAddresses {
		seedNodes[i] = SeedNode{
			ID:      fmt.Sprintf("seed-%d", i),
			Address: address,
		}
	}
	return &BootstrapManager{
		seedNodes:        seedNodes,
		connectedNodes:   make(map[string]*Node),
		dht:              NewDHT(),
		httpClient:       &http.Client{Timeout: connectionTimeout},
		connectionTimeout: connectionTimeout,
	}, nil
}

// DiscoverPeers connects to seed nodes to discover additional peers in the network.
func (bm *BootstrapManager) DiscoverPeers() error {
	for _, seedNode := range bm.seedNodes {
		err := bm.connectToSeedNode(seedNode)
		if err != nil {
			return err
		}
	}
	return nil
}

// connectToSeedNode connects to a seed node to discover peers.
func (bm *BootstrapManager) connectToSeedNode(seedNode SeedNode) error {
	resp, err := bm.httpClient.Get(fmt.Sprintf("http://%s/peers", seedNode.Address))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var peers []Node
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return err
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()
	for _, peer := range peers {
		bm.connectedNodes[peer.ID] = &peer
		bm.dht.AddNode(&peer)
	}

	return nil
}

// RegisterNode registers a new node in the network.
func (bm *BootstrapManager) RegisterNode(node *Node) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if _, exists := bm.connectedNodes[node.ID]; exists {
		return errors.New("node already registered")
	}

	if err := bm.verifyNodeIdentity(node); err != nil {
		return err
	}

	bm.dht.AddNode(node)
	bm.connectedNodes[node.ID] = node

	return nil
}

// verifyNodeIdentity verifies the identity of a new node using cryptographic techniques.
func (bm *BootstrapManager) verifyNodeIdentity(node *Node) error {
	// Implement identity verification logic here (e.g., checking a digital signature)
	return nil
}

// GenerateKeyPair generates a new RSA key pair for a node.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// ExportPublicKey exports a public key to a PEM encoded string.
func ExportPublicKey(pubkey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubBytes), nil
}

// ImportPublicKey imports a PEM encoded public key string.
func ImportPublicKey(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubkey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return pubkey, nil
}

// Node represents a node in the blockchain network.
type Node struct {
	ID         string
	Address    string
	PublicKey  *rsa.PublicKey
	LastSeen   time.Time
	Health     NodeHealth
	GeoLocation GeoLocation
}

// NodeHealth represents the health status of a node.
type NodeHealth struct {
	CPUUsage    float64
	MemoryUsage float64
	Latency     time.Duration
}

// GeoLocation represents the geographical location of a node.
type GeoLocation struct {
	Latitude  float64
	Longitude float64
}

// DHT represents a Distributed Hash Table for node discovery.
type DHT struct {
	mu    sync.Mutex
	nodes map[string]*Node
}

// NewDHT creates a new DHT instance.
func NewDHT() *DHT {
	return &DHT{
		nodes: make(map[string]*Node),
	}
}

// AddNode adds a node to the DHT.
func (d *DHT) AddNode(node *Node) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes[node.ID] = node
}

// FindNode finds a node in the DHT.
func (d *DHT) FindNode(id string) (*Node, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	node, exists := d.nodes[id]
	return node, exists
}

// SeedNodeRegistrationHandler handles the registration of seed nodes.
func (bm *BootstrapManager) SeedNodeRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var node SeedNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := bm.RegisterSeedNode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RegisterSeedNode registers a new seed node in the network.
func (bm *BootstrapManager) RegisterSeedNode(seedNode *SeedNode) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	for _, node := range bm.seedNodes {
		if node.ID == seedNode.ID {
			return errors.New("seed node already registered")
		}
	}

	bm.seedNodes = append(bm.seedNodes, *seedNode)
	return nil
}

func main() {
	seedNodeAddresses := []string{"seed1.synnergy.com:8080", "seed2.synnergy.com:8080"}
	connectionTimeout := 10 * time.Second

	manager, err := NewBootstrapManager(seedNodeAddresses, connectionTimeout)
	if err != nil {
		fmt.Printf("Error creating BootstrapManager: %v\n", err)
		return
	}

	if err := manager.DiscoverPeers(); err != nil {
		fmt.Printf("Error discovering peers: %v\n", err)
	}

	http.HandleFunc("/register-seed", manager.SeedNodeRegistrationHandler)
	http.ListenAndServe(":8080", nil)
}
