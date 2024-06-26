package firewalls

import (
	"net"
	"sync"
	"time"
	"fmt"
)

// ConnectionState holds the state and details of a network connection.
type ConnectionState struct {
	SourceIP       net.IP
	DestinationIP  net.IP
	Protocol       string
	StartTime      time.Time
	LastActiveTime time.Time
	State          string
}

// StatefulFirewall manages connection states and applies firewall rules.
type StatefulFirewall struct {
	Connections map[string]*ConnectionState
	Rules       []*Rule
	mu          sync.RWMutex
}

// NewStatefulFirewall initializes a new StatefulFirewall.
func NewStatefulFirewall() *StatefulFirewall {
	return &StatefulFirewall{
		Connections: make(map[string]*ConnectionState),
		Rules:       make([]*Rule, 0),
	}
}

// AddConnection registers a new connection in the firewall.
func (sf *StatefulFirewall) AddConnection(conn net.Conn) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	key := conn.RemoteAddr().String() + "-" + conn.LocalAddr().String()
	sf.Connections[key] = &ConnectionState{
		SourceIP:       net.ParseIP(conn.RemoteAddr().String()),
		DestinationIP:  net.ParseIP(conn.LocalAddr().String()),
		StartTime:      time.Now(),
		LastActiveTime: time.Now(),
		State:          "NEW",
	}
	fmt.Println("Added new connection:", key)
}

// CheckAndUpdateState checks and updates the state of connections based on rules.
func (sf *StatefulFirewall) CheckAndUpdateState() {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	for key, conn := range sf.Connections {
		if time.Since(conn.LastActiveTime) > 5*time.Minute {
			delete(sf.Connections, key)
			fmt.Println("Connection timed out and removed:", key)
		}
	}
}

// EvaluatePacket evaluates incoming packets against the stateful rules.
func (sf *StatefulFirewall) EvaluatePacket(packet net.PacketConn) bool {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	// Simplified evaluation logic based on connection state
	for _, rule := range sf.Rules {
		if rule.Action == "Deny" {
			return false
		}
	}
	return true
}

// MonitorTraffic starts a routine to monitor and adapt firewall rules dynamically.
func (sf *StatefulFirewall) MonitorTraffic() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			sf.CheckAndUpdateState()
			// Implement dynamic rule adaptation based on traffic analysis
			fmt.Println("Monitoring and adapting rules based on traffic...")
		}
	}()
}

// Define rules and policies for initializing the stateful firewall.
func init() {
	firewall := NewStatefulFirewall()
	firewall.MonitorTraffic()
}
