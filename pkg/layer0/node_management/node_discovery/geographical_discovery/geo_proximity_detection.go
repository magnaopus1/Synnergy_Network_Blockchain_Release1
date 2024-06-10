package geographical_discovery

import (
	"errors"
	"math"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Node represents a node in the network with geographic coordinates.
type Node struct {
	ID        string
	IP        string
	Latitude  float64
	Longitude float64
}

// GeoProximityDetector handles geographic proximity detection.
type GeoProximityDetector struct {
	mu          sync.Mutex
	nodes       map[string]*Node
	geoDB       *geoip2.Reader
	seedNodes   []string
	maxDistance float64
}

// NewGeoProximityDetector creates a new GeoProximityDetector.
func NewGeoProximityDetector(geoDBPath string, seedNodes []string, maxDistance float64) (*GeoProximityDetector, error) {
	db, err := geoip2.Open(geoDBPath)
	if err != nil {
		return nil, err
	}

	return &GeoProximityDetector{
		nodes:       make(map[string]*Node),
		geoDB:       db,
		seedNodes:   seedNodes,
		maxDistance: maxDistance,
	}, nil
}

// AddNode adds a new node to the proximity detector.
func (g *GeoProximityDetector) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
}

// RemoveNode removes a node from the proximity detector.
func (g *GeoProximityDetector) RemoveNode(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.nodes, nodeID)
}

// FindClosestNodes finds the closest nodes to a given IP address within the maxDistance.
func (g *GeoProximityDetector) FindClosestNodes(ip string) ([]*Node, error) {
	record, err := g.geoDB.City(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	targetLat := record.Location.Latitude
	targetLon := record.Location.Longitude

	g.mu.Lock()
	defer g.mu.Unlock()

	var closestNodes []*Node
	for _, node := range g.nodes {
		distance := calculateDistance(targetLat, targetLon, node.Latitude, node.Longitude)
		if distance <= g.maxDistance {
			closestNodes = append(closestNodes, node)
		}
	}

	return closestNodes, nil
}

// BootstrapNode bootstraps a new node by adding it and finding the closest seed nodes.
func (g *GeoProximityDetector) BootstrapNode(ip string) ([]*Node, error) {
	closestNodes, err := g.FindClosestNodes(ip)
	if err != nil {
		return nil, err
	}

	for _, seedNode := range g.seedNodes {
		seedIP := extractIP(seedNode)
		seedRecord, err := g.geoDB.City(net.ParseIP(seedIP))
		if err != nil {
			return nil, err
		}

		seedLat := seedRecord.Location.Latitude
		seedLon := seedRecord.Location.Longitude
		closestNodes = append(closestNodes, &Node{
			ID:        generateNodeID(seedIP),
			IP:        seedIP,
			Latitude:  seedLat,
			Longitude: seedLon,
		})
	}

	return closestNodes, nil
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

// extractIP extracts the IP address from a given seed node address.
func extractIP(address string) string {
	return strings.Split(address, ":")[0]
}
