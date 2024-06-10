package networking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Connection represents a network connection in the pool
type Connection struct {
	ID       string
	Conn     net.Conn
	LastUsed time.Time
}

// ConnectionPool manages a pool of network connections
type ConnectionPool struct {
	mutex        sync.Mutex
	connections  map[string]*Connection
	maxIdleTime  time.Duration
	cleanupTimer *time.Ticker
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxIdleTime time.Duration, cleanupInterval time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		connections:  make(map[string]*Connection),
		maxIdleTime:  maxIdleTime,
		cleanupTimer: time.NewTicker(cleanupInterval),
	}

	go pool.cleanupConnections()
	return pool
}

// AddConnection adds a connection to the pool
func (p *ConnectionPool) AddConnection(id string, conn net.Conn) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.connections[id] = &Connection{
		ID:       id,
		Conn:     conn,
		LastUsed: time.Now(),
	}
}

// GetConnection retrieves a connection from the pool
func (p *ConnectionPool) GetConnection(id string) (net.Conn, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if conn, exists := p.connections[id]; exists {
		conn.LastUsed = time.Now()
		return conn.Conn, nil
	}
	return nil, errors.New("connection not found")
}

// RemoveConnection removes a connection from the pool
func (p *ConnectionPool) RemoveConnection(id string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if conn, exists := p.connections[id]; exists {
		conn.Conn.Close()
		delete(p.connections, id)
	}
}

// cleanupConnections cleans up idle connections
func (p *ConnectionPool) cleanupConnections() {
	for range p.cleanupTimer.C {
		p.mutex.Lock()
		for id, conn := range p.connections {
			if time.Since(conn.LastUsed) > p.maxIdleTime {
				conn.Conn.Close()
				delete(p.connections, id)
			}
		}
		p.mutex.Unlock()
	}
}

// SecureHash generates a secure hash for connection IDs
func SecureHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Connect establishes a connection to a remote node
func Connect(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Example usage
func main() {
	// Create a connection pool with a max idle time of 10 minutes and cleanup interval of 1 minute
	pool := NewConnectionPool(10*time.Minute, 1*time.Minute)

	// Example addresses
	addresses := []string{"192.168.1.1:8080", "192.168.1.2:8080", "192.168.1.3:8080"}

	// Connect to nodes and add connections to the pool
	for _, addr := range addresses {
		conn, err := Connect(addr)
		if err != nil {
			fmt.Printf("Failed to connect to %s: %v\n", addr, err)
			continue
		}
		id := SecureHash(addr)
		pool.AddConnection(id, conn)
	}

	// Retrieve a connection from the pool
	conn, err := pool.GetConnection(SecureHash("192.168.1.1:8080"))
	if err != nil {
		fmt.Println("Error retrieving connection:", err)
	} else {
		fmt.Println("Successfully retrieved connection:", conn)
	}

	// Simulate some wait time
	time.Sleep(2 * time.Minute)

	// Clean up
	pool.RemoveConnection(SecureHash("192.168.1.1:8080"))
}
