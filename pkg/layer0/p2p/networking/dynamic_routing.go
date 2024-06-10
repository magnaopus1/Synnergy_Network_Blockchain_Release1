package networking

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// RoutingTable represents the routing table for dynamic routing
type RoutingTable struct {
	mutex         sync.Mutex
	routes        map[string]*Route
	lastUpdated   time.Time
	updateTimeout time.Duration
}

// Route represents a network route
type Route struct {
	Destination string
	NextHop     string
	Metric      int
	LastUsed    time.Time
}

// NewRoutingTable creates a new routing table
func NewRoutingTable(updateTimeout time.Duration) *RoutingTable {
	return &RoutingTable{
		routes:        make(map[string]*Route),
		updateTimeout: updateTimeout,
		lastUpdated:   time.Now(),
	}
}

// AddRoute adds a route to the routing table
func (rt *RoutingTable) AddRoute(destination, nextHop string, metric int) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	rt.routes[destination] = &Route{
		Destination: destination,
		NextHop:     nextHop,
		Metric:      metric,
		LastUsed:    time.Now(),
	}
	rt.lastUpdated = time.Now()
}

// GetRoute retrieves a route from the routing table
func (rt *RoutingTable) GetRoute(destination string) (*Route, error) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	if route, exists := rt.routes[destination]; exists {
		route.LastUsed = time.Now()
		return route, nil
	}
	return nil, errors.New("route not found")
}

// RemoveRoute removes a route from the routing table
func (rt *RoutingTable) RemoveRoute(destination string) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	delete(rt.routes, destination)
}

// UpdateRoutes updates the routing table based on network conditions
func (rt *RoutingTable) UpdateRoutes(newRoutes map[string]*Route) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for dest, route := range newRoutes {
		rt.routes[dest] = route
	}
	rt.lastUpdated = time.Now()
}

// CleanupOldRoutes removes routes that haven't been used for a defined period
func (rt *RoutingTable) CleanupOldRoutes(maxIdleTime time.Duration) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()
	for dest, route := range rt.routes {
		if time.Since(route.LastUsed) > maxIdleTime {
			delete(rt.routes, dest)
		}
	}
}

// DynamicRouter represents a dynamic router for the blockchain network
type DynamicRouter struct {
	routingTable   *RoutingTable
	updateInterval time.Duration
	cleanupInterval time.Duration
	stopChannel    chan struct{}
}

// NewDynamicRouter creates a new dynamic router
func NewDynamicRouter(updateInterval, cleanupInterval, maxIdleTime time.Duration) *DynamicRouter {
	router := &DynamicRouter{
		routingTable:   NewRoutingTable(maxIdleTime),
		updateInterval: updateInterval,
		cleanupInterval: cleanupInterval,
		stopChannel:    make(chan struct{}),
	}

	go router.runUpdates()
	go router.runCleanup()

	return router
}

// runUpdates periodically updates the routing table based on network conditions
func (dr *DynamicRouter) runUpdates() {
	ticker := time.NewTicker(dr.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Simulate fetching new routes
			newRoutes := dr.fetchNetworkRoutes()
			dr.routingTable.UpdateRoutes(newRoutes)
		case <-dr.stopChannel:
			return
		}
	}
}

// runCleanup periodically cleans up old routes
func (dr *DynamicRouter) runCleanup() {
	ticker := time.NewTicker(dr.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dr.routingTable.CleanupOldRoutes(dr.routingTable.updateTimeout)
		case <-dr.stopChannel:
			return
		}
	}
}

// fetchNetworkRoutes simulates fetching new network routes (placeholder)
func (dr *DynamicRouter) fetchNetworkRoutes() map[string]*Route {
	// Placeholder for actual network route fetching logic
	// This should be replaced with actual dynamic route discovery logic
	return map[string]*Route{
		"192.168.1.1": {Destination: "192.168.1.1", NextHop: "192.168.1.254", Metric: 1, LastUsed: time.Now()},
		"192.168.1.2": {Destination: "192.168.1.2", NextHop: "192.168.1.254", Metric: 2, LastUsed: time.Now()},
	}
}

// Stop stops the dynamic router
func (dr *DynamicRouter) Stop() {
	close(dr.stopChannel)
}

// Example usage
func main() {
	// Create a dynamic router with update interval of 1 minute and cleanup interval of 5 minutes
	router := NewDynamicRouter(1*time.Minute, 5*time.Minute, 10*time.Minute)

	// Simulate adding a route
	router.routingTable.AddRoute("192.168.1.1", "192.168.1.254", 1)

	// Retrieve and print the route
	route, err := router.routingTable.GetRoute("192.168.1.1")
	if err != nil {
		fmt.Println("Error retrieving route:", err)
	} else {
		fmt.Printf("Retrieved route: %+v\n", route)
	}

	// Simulate stopping the router after some time
	time.Sleep(2 * time.Minute)
	router.Stop()
}
