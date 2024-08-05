package network_monitoring

import (
	"log"
	"net"
	"time"
)

// NodeStatus represents the connectivity status of a node
type NodeStatus struct {
	NodeID     string
	IP         string
	Status     string
	LastChecked time.Time
}

// NetworkMonitor is responsible for monitoring the connectivity of nodes in the network
type NetworkMonitor struct {
	nodes map[string]*NodeStatus
}

// NewNetworkMonitor creates a new NetworkMonitor instance
func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		nodes: make(map[string]*NodeStatus),
	}
}

// AddNode adds a new node to the network monitor
func (nm *NetworkMonitor) AddNode(nodeID, ip string) {
	nm.nodes[nodeID] = &NodeStatus{
		NodeID: nodeID,
		IP:     ip,
		Status: "unknown",
	}
}

// RemoveNode removes a node from the network monitor
func (nm *NetworkMonitor) RemoveNode(nodeID string) {
	delete(nm.nodes, nodeID)
}

// CheckConnectivity checks the connectivity of all nodes in the network
func (nm *NetworkMonitor) CheckConnectivity() {
	for _, node := range nm.nodes {
		go nm.checkNode(node)
	}
}

func (nm *NetworkMonitor) checkNode(node *NodeStatus) {
	conn, err := net.DialTimeout("tcp", node.IP, 5*time.Second)
	if err != nil {
		node.Status = "offline"
	} else {
		node.Status = "online"
		conn.Close()
	}
	node.LastChecked = time.Now()
}

// GetNodeStatus returns the status of a specific node
func (nm *NetworkMonitor) GetNodeStatus(nodeID string) *NodeStatus {
	return nm.nodes[nodeID]
}

// GetAllNodeStatuses returns the status of all nodes
func (nm *NetworkMonitor) GetAllNodeStatuses() map[string]*NodeStatus {
	return nm.nodes
}

// AlertSystem sends alerts based on node statuses
type AlertSystem struct {
	alertThreshold time.Duration
	notificationCh chan string
}

// NewAlertSystem creates a new AlertSystem instance
func NewAlertSystem(alertThreshold time.Duration) *AlertSystem {
	return &AlertSystem{
		alertThreshold: alertThreshold,
		notificationCh: make(chan string),
	}
}

// MonitorNodeStatus monitors the status of nodes and sends alerts if they are offline for too long
func (as *AlertSystem) MonitorNodeStatus(nm *NetworkMonitor) {
	for {
		time.Sleep(as.alertThreshold)
		for _, node := range nm.GetAllNodeStatuses() {
			if node.Status == "offline" && time.Since(node.LastChecked) > as.alertThreshold {
				as.notificationCh <- "Node " + node.NodeID + " is offline for more than " + as.alertThreshold.String()
			}
		}
	}
}

// GetNotifications returns the notification channel
func (as *AlertSystem) GetNotifications() <-chan string {
	return as.notificationCh
}

// LoggingSystem logs all node status changes
type LoggingSystem struct {
	logCh chan string
}

// NewLoggingSystem creates a new LoggingSystem instance
func NewLoggingSystem() *LoggingSystem {
	return &LoggingSystem{
		logCh: make(chan string),
	}
}

// LogNodeStatus logs the status changes of nodes
func (ls *LoggingSystem) LogNodeStatus(nm *NetworkMonitor) {
	for {
		time.Sleep(1 * time.Minute)
		for _, node := range nm.GetAllNodeStatuses() {
			ls.logCh <- "Node " + node.NodeID + " status: " + node.Status + " at " + node.LastChecked.String()
		}
	}
}

// GetLogEntries returns the log entries channel
func (ls *LoggingSystem) GetLogEntries() <-chan string {
	return ls.logCh
}

// MonitoringService is the main service that runs network monitoring, alerting, and logging
type MonitoringService struct {
	nm  *NetworkMonitor
	as  *AlertSystem
	ls  *LoggingSystem
}

// NewMonitoringService creates a new MonitoringService instance
func NewMonitoringService(nm *NetworkMonitor, as *AlertSystem, ls *LoggingSystem) *MonitoringService {
	return &MonitoringService{
		nm: nm,
		as: as,
		ls: ls,
	}
}

// StartMonitoring starts the monitoring service
func (ms *MonitoringService) StartMonitoring() {
	go ms.nm.CheckConnectivity()
	go ms.as.MonitorNodeStatus(ms.nm)
	go ms.ls.LogNodeStatus(ms.nm)
}

func main() {
	nm := NewNetworkMonitor()
	nm.AddNode("node1", "192.168.1.1:30303")
	nm.AddNode("node2", "192.168.1.2:30303")

	as := NewAlertSystem(10 * time.Second)
	ls := NewLoggingSystem()

	ms := NewMonitoringService(nm, as, ls)
	ms.StartMonitoring()

	// Listen for alerts
	go func() {
		for alert := range as.GetNotifications() {
			log.Println(alert)
		}
	}()

	// Listen for log entries
	go func() {
		for logEntry := range ls.GetLogEntries() {
			log.Println(logEntry)
		}
	}()

	// Simulate running indefinitely
	select {}
}
