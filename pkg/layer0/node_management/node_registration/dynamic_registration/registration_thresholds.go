package dynamic_registration

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID             string    `json:"id"`
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	DiskUsage      float64   `json:"disk_usage"`
	LastRegistered time.Time `json:"last_registered"`
}

// RegistrationManager manages dynamic registration thresholds and node registrations.
type RegistrationManager struct {
	nodes            map[string]*Node
	mu               sync.Mutex
	thresholds       RegistrationThresholds
	adjustInterval   time.Duration
	adjustmentFactor float64
}

// RegistrationThresholds represents the thresholds for registering new nodes.
type RegistrationThresholds struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
}

// NewRegistrationManager creates a new RegistrationManager instance.
func NewRegistrationManager(interval time.Duration, factor float64) *RegistrationManager {
	return &RegistrationManager{
		nodes:            make(map[string]*Node),
		thresholds:       RegistrationThresholds{CPUUsage: 0.75, MemoryUsage: 0.75, DiskUsage: 0.75},
		adjustInterval:   interval,
		adjustmentFactor: factor,
	}
}

// RegisterNode registers a new node in the system.
func (rm *RegistrationManager) RegisterNode(id string, cpuUsage, memoryUsage, diskUsage float64) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if cpuUsage > rm.thresholds.CPUUsage || memoryUsage > rm.thresholds.MemoryUsage || diskUsage > rm.thresholds.DiskUsage {
		return errors.New("node usage exceeds registration thresholds")
	}

	rm.nodes[id] = &Node{
		ID:             id,
		CPUUsage:       cpuUsage,
		MemoryUsage:    memoryUsage,
		DiskUsage:      diskUsage,
		LastRegistered: time.Now(),
	}

	return nil
}

// GetNode returns the information of a registered node.
func (rm *RegistrationManager) GetNode(id string) (*Node, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	node, exists := rm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}

	return node, nil
}

// AdjustThresholds dynamically adjusts the registration thresholds based on network conditions.
func (rm *RegistrationManager) AdjustThresholds() {
	for {
		time.Sleep(rm.adjustInterval)
		rm.mu.Lock()

		totalNodes := len(rm.nodes)
		if totalNodes == 0 {
			rm.mu.Unlock()
			continue
		}

		var totalCPU, totalMemory, totalDisk float64
		for _, node := range rm.nodes {
			totalCPU += node.CPUUsage
			totalMemory += node.MemoryUsage
			totalDisk += node.DiskUsage
		}

		averageCPU := totalCPU / float64(totalNodes)
		averageMemory := totalMemory / float64(totalNodes)
		averageDisk := totalDisk / float64(totalNodes)

		rm.thresholds.CPUUsage = averageCPU * rm.adjustmentFactor
		rm.thresholds.MemoryUsage = averageMemory * rm.adjustmentFactor
		rm.thresholds.DiskUsage = averageDisk * rm.adjustmentFactor

		rm.mu.Unlock()
	}
}

// ServeHTTP handles HTTP requests for dynamic registration.
func (rm *RegistrationManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		rm.handleNodeRegistration(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNodeRegistration handles the HTTP request for node registration.
func (rm *RegistrationManager) handleNodeRegistration(w http.ResponseWriter, r *http.Request) {
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := rm.RegisterNode(node.ID, node.CPUUsage, node.MemoryUsage, node.DiskUsage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// StartMonitoring starts the process of adjusting registration thresholds.
func (rm *RegistrationManager) StartMonitoring() {
	go rm.AdjustThresholds()
}

func main() {
	regManager := NewRegistrationManager(10*time.Minute, 1.2)
	http.Handle("/register", regManager)
	go regManager.StartMonitoring()
	http.ListenAndServe(":8080", nil)
}
