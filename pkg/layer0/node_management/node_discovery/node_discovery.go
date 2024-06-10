package node_management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	discovery "github.com/libp2p/go-libp2p-discovery"
	"github.com/libp2p/go-libp2p-crypto"
	"github.com/multiformats/go-multiaddr"
)

// Node represents a node in the network.
type Node struct {
	ID   string
	IP   string
	Port int
}

// NodeDiscovery handles the discovery of new nodes and management of peer connections.
type NodeDiscovery struct {
	mu              sync.Mutex
	nodes           map[string]*Node
	host            host.Host
	dht             *dht.IpfsDHT
	routingDiscovery *discovery.RoutingDiscovery
	broadcastCh     chan *Node
	listenAddr      string
	privateKey      crypto.PrivKey
}

// NewNodeDiscovery creates a new NodeDiscovery.
func NewNodeDiscovery(listenAddr string, privateKey crypto.PrivKey) *NodeDiscovery {
	return &NodeDiscovery{
		nodes:       make(map[string]*Node),
		broadcastCh: make(chan *Node),
		listenAddr:  listenAddr,
		privateKey:  privateKey,
	}
}

// Start starts the node discovery process.
func (nd *NodeDiscovery) Start() error {
	var err error
	ctx := context.Background()
	nd.host, err = libp2p.New(libp2p.Identity(nd.privateKey))
	if err != nil {
		return fmt.Errorf("failed to create libp2p host: %w", err)
	}

	nd.dht, err = dht.New(ctx, nd.host)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}

	nd.routingDiscovery = discovery.NewRoutingDiscovery(nd.dht)
	discovery.Advertise(ctx, nd.routingDiscovery, "synthron")

	go nd.listenForPeers(ctx)
	go nd.handleBroadcasts()

	return nil
}

// RegisterNode registers a new node in the network.
func (nd *NodeDiscovery) RegisterNode(node *Node) {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	nd.nodes[node.ID] = node
}

// RemoveNode removes a node from the network.
func (nd *NodeDiscovery) RemoveNode(nodeID string) {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	delete(nd.nodes, nodeID)
}

// BroadcastNode broadcasts the presence of a node to the network.
func (nd *NodeDiscovery) BroadcastNode(node *Node) {
	nd.broadcastCh <- node
}

// handleBroadcasts handles broadcasting node information.
func (nd *NodeDiscovery) handleBroadcasts() {
	for {
		node := <-nd.broadcastCh
		nd.mu.Lock()
		for _, peer := range nd.nodes {
			go nd.sendNodeInfo(node, peer)
		}
		nd.mu.Unlock()
	}
}

// listenForPeers listens for incoming peer connections.
func (nd *NodeDiscovery) listenForPeers(ctx context.Context) {
	peerChan, err := nd.routingDiscovery.FindPeers(ctx, "synthron")
	if err != nil {
		fmt.Printf("Error finding peers: %v\n", err)
		return
	}

	for peerInfo := range peerChan {
		if peerInfo.ID == nd.host.ID() {
			continue
		}

		err := nd.host.Connect(ctx, peerInfo)
		if err != nil {
			fmt.Printf("Error connecting to peer: %v\n", err)
		} else {
			fmt.Printf("Connected to peer: %s\n", peerInfo.ID.Pretty())
		}
	}
}

// sendNodeInfo sends node information to a peer.
func (nd *NodeDiscovery) sendNodeInfo(node *Node, peer *Node) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
	if err != nil {
		fmt.Printf("Error connecting to peer %s: %v\n", peer.ID, err)
		return
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(node)
	if err != nil {
		fmt.Printf("Error sending node information to peer %s: %v\n", peer.ID, err)
	}
}

// generateNodeID generates a unique node ID using SHA-256 for added security.
func generateNodeID(ip string, port int) (string, error) {
	data := fmt.Sprintf("%s:%d", ip, port)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// Usage Example for initializing the NodeDiscovery and broadcasting a node.
func main() {
	listenAddr := "/ip4/0.0.0.0/tcp/0"
	privateKey, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		panic(err)
	}

	protocol := NewNodeDiscovery(listenAddr, privateKey)
	err = protocol.Start()
	if err != nil {
		panic(err)
	}

	ip := "192.168.1.1"
	port := 8001
	nodeID, err := generateNodeID(ip, port)
	if err != nil {
		panic(err)
	}

	node := &Node{
		ID:   nodeID,
		IP:   ip,
		Port: port,
	}

	protocol.RegisterNode(node)
	protocol.BroadcastNode(node)

	// Keep the main function running to allow the protocol to operate.
	select {}
}
