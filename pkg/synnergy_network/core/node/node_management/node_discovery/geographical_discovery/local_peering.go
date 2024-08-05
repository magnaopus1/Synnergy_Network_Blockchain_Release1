package geographical_discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/crypto/argon2"
)

// Node represents a node in the network with geographic coordinates and peering information.
type Node struct {
	ID        string
	IP        string
	Latitude  float64
	Longitude float64
}

// LocalPeeringManager handles local peering of nodes based on geographic proximity.
type LocalPeeringManager struct {
	mu          sync.Mutex
	nodes       map[string]*Node
	geoDB       *geoip2.Reader
	maxDistance float64
}

// NewLocalPeeringManager creates a new LocalPeeringManager.
func NewLocalPeeringManager(geoDBPath string, maxDistance float64) (*LocalPeeringManager, error) {
	db, err := geoip2.Open(geoDBPath)
	if err != nil {
		return nil, err
	}

	return &LocalPeeringManager{
		nodes:       make(map[string]*Node),
		geoDB:       db,
		maxDistance: maxDistance,
	}, nil
}

// AddNode adds a new node to the local peering manager.
func (l *LocalPeeringManager) AddNode(node *Node) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nodes[node.ID] = node
}

// RemoveNode removes a node from the local peering manager.
func (l *LocalPeeringManager) RemoveNode(nodeID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.nodes, nodeID)
}

// FindLocalPeers finds the local peers closest to a given IP address within the maxDistance.
func (l *LocalPeeringManager) FindLocalPeers(ip string) ([]*Node, error) {
	record, err := l.geoDB.City(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	targetLat := record.Location.Latitude
	targetLon := record.Location.Longitude

	l.mu.Lock()
	defer l.mu.Unlock()

	var localPeers []*Node
	for _, node := range l.nodes {
		distance := calculateDistance(targetLat, targetLon, node.Latitude, node.Longitude)
		if distance <= l.maxDistance {
			localPeers = append(localPeers, node)
		}
	}

	return localPeers, nil
}

// BootstrapNode bootstraps a new node by adding it and finding the closest peers.
func (l *LocalPeeringManager) BootstrapNode(ip string) ([]*Node, error) {
	closestPeers, err := l.FindLocalPeers(ip)
	if err != nil {
		return nil, err
	}

	return closestPeers, nil
}

// calculateDistance calculates the Haversine distance between two points.
func calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371.0 // Earth's radius in kilometers
	dLat := degreesToRadians(lat2 - lat1)
	dLon := degreesToRadians(lon2 - lon1)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(degreesToRadians(lat1))*math.Cos(degreesToRadians(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}

// degreesToRadians converts degrees to radians.
func degreesToRadians(degrees float64) float64 {
	return degrees * math.Pi / 180
}

// generateNodeID generates a unique node ID based on the node's IP address.
func generateNodeID(ip string) string {
	hash := sha256.New()
	hash.Write([]byte(ip))
	return hex.EncodeToString(hash.Sum(nil))
}

// extractIP extracts the IP address from a given address string.
func extractIP(address string) string {
	return strings.Split(address, ":")[0]
}

// secureNodeID generates a secure node ID using Argon2 for enhanced security.
func secureNodeID(ip string, salt []byte) string {
	hash := argon2.IDKey([]byte(ip), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// CreateSalt generates a new salt for use in Argon2 hashing.
func CreateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// Usage Example for initializing the LocalPeeringManager and adding a node.
func main() {
	geoDBPath := "path/to/GeoLite2-City.mmdb"
	maxDistance := 50.0 // Max distance in kilometers

	manager, err := NewLocalPeeringManager(geoDBPath, maxDistance)
	if err != nil {
		panic(err)
	}

	ip := "192.168.1.1"
	salt, err := CreateSalt()
	if err != nil {
		panic(err)
	}

	nodeID := secureNodeID(ip, salt)
	node := &Node{
		ID:        nodeID,
		IP:        ip,
		Latitude:  37.7749, // Example latitude
		Longitude: -122.4194, // Example longitude
	}

	manager.AddNode(node)

	// Finding local peers
	localPeers, err := manager.FindLocalPeers(ip)
	if err != nil {
		panic(err)
	}

	for _, peer := range localPeers {
		fmt.Printf("Local Peer: %+v\n", peer)
	}
}
