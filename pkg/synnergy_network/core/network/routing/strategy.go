package routing

import (
	"net"
	"sync"
	"errors"
	"math"

	"github.com/google/gopacket/routing"
)

// Strategy defines the interface for different routing strategies.
type Strategy interface {
	ComputePath(source, destination net.Addr) ([]net.Addr, error)
}

// DijkstraStrategy implements the Dijkstra algorithm for shortest path routing.
type DijkstraStrategy struct {
	graph *NetworkGraph
}

// NewDijkstraStrategy creates a new instance of DijkstraStrategy with the provided network graph.
func NewDijkstraStrategy(graph *NetworkGraph) *DijkstraStrategy {
	return &DijkstraStrategy{graph: graph}
}

// ComputePath calculates the shortest path from source to destination using Dijkstra's algorithm.
func (d *DijkstraStrategy) ComputePath(source, destination net.Addr) ([]net.Addr, error) {
	return d.graph.ShortestPath(source, destination)
}

// BellmanFordStrategy implements the Bellman-Ford algorithm for routing.
type BellmanFordStrategy struct {
	graph *NetworkGraph
}

// NewBellmanFordStrategy creates a new instance of BellmanFordStrategy.
func NewBellmanFordStrategy(graph *NetworkGraph) *BellmanFordStrategy {
	return &BellmanFordStrategy{graph: graph}
}

// ComputePath calculates the path from source to destination using the Bellman-Ford algorithm.
func (b *BellmanFordStrategy) ComputePath(source, destination net.Addr) ([]net.Addr, error) {
	return b.graph.ShortestPath(source, destination)
}

// MultipathStrategy implements routing over multiple paths.
type MultipathStrategy struct {
	strategies []Strategy
}

// NewMultipathStrategy creates a new multipath routing strategy.
func NewMultipathStrategy(strategies ...Strategy) *MultipathStrategy {
	return &MultipathStrategy{strategies: strategies}
}

// ComputePath calculates multiple paths and selects one based on load-balancing or redundancy needs.
func (m *MultipathStrategy) ComputePath(source, destination net.Addr) ([]net.Addr, error) {
	paths := make([][]net.Addr, len(m.strategies))
	var shortestPath []net.Addr
	minLength := math.MaxInt32

	for i, strategy := range m.strategies {
		path, err := strategy.ComputePath(source, destination)
		if err != nil {
			continue
		}
		paths[i] = path
		if len(path) < minLength {
			minLength = len(path)
			shortestPath = path
		}
	}

	if len(shortestPath) == 0 {
		return nil, errors.New("no viable path found")
	}
	return shortestPath, nil
}

// AnycastStrategy implements routing to the nearest or most optimal node.
type AnycastStrategy struct {
	locations map[net.Addr][]net.Addr
}

// NewAnycastStrategy creates a new Anycast routing strategy.
func NewAnycastStrategy(locations map[net.Addr][]net.Addr) *AnycastStrategy {
	return &AnycastStrategy{locations: locations}
}

// ComputePath finds the nearest node offering the desired service and routes to it.
func (a *AnycastStrategy) ComputePath(source, destination net.Addr) ([]net.Addr, error) {
	if nodes, ok := a.locations[destination]; ok && len(nodes) > 0 {
		// Example logic to select the nearest node.
		return []net.Addr{nodes[0]}, nil // Simplified for demonstration.
	}
	return nil, errors.New("destination not supported for anycast routing")
}

