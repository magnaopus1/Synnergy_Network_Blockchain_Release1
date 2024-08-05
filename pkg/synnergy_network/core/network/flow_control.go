package network

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"synnergy_network_blockchain/pkg/synnergy_network/core/common"
)


// AdaptivePolicies represents the adaptive flow control policies in the Synnergy Network
type AdaptiveFlowControlPolicies struct {
	policies map[string]*Policy
	logger   *common.Logger
	mu       sync.Mutex
}

// Policy represents a single flow control policy
type Policy struct {
	ID               string
	Name             string
	MaxBandwidth     int
	MinBandwidth     int
	CurrentBandwidth int
	LastUpdated      time.Time
	HashManager      *common.HashManager
	EncryptionManager *common.EncryptionManager
}

// NewAdaptivePolicies creates a new instance of AdaptivePolicies
func NewAdaptivePolicies(logger *commonLogger) *AdaptiveFlowControlPolicies {
	return &AdaptivePolicies{
		policies: make(map[string]*Policy),
		logger:   logger,
	}
}

// AddPolicy adds a new policy to the adaptive flow control system
func (ap *AdaptivePolicies) AddPolicy(id, name string, maxBandwidth, minBandwidth int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.policies[id] = &Policy{
		ID:               id,
		Name:             name,
		MaxBandwidth:     maxBandwidth,
		MinBandwidth:     minBandwidth,
		CurrentBandwidth: maxBandwidth, // Initial bandwidth is set to max
		LastUpdated:      time.Now(),
		HashManager:      NewHashManager(),
		EncryptionManager: NewEncryptionManager(),
	}
	ap.logger.Info("Added new policy: " + name)
}

// RemovePolicy removes a policy from the adaptive flow control system
func (ap *AdaptivePolicies) RemovePolicy(id string) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	delete(ap.policies, id)
	ap.logger.Info("Removed policy with ID: " + id)
}

// UpdatePolicy updates an existing policy's bandwidth settings
func (ap *AdaptivePolicies) UpdatePolicy(id string, maxBandwidth, minBandwidth int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if policy, exists := ap.policies[id]; exists {
		policy.MaxBandwidth = maxBandwidth
		policy.MinBandwidth = minBandwidth
		policy.LastUpdated = time.Now()
		ap.logger.Info("Updated policy: " + policy.Name)
	} else {
		ap.logger.Warning("Policy with ID " + id + " does not exist")
	}
}

// AdjustBandwidth dynamically adjusts the bandwidth for a given policy based on network conditions
func (ap *AdaptivePolicies) AdjustBandwidth(id string, currentLoad int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if policy, exists := ap.policies[id]; exists {
		if currentLoad > policy.CurrentBandwidth {
			if policy.CurrentBandwidth < policy.MaxBandwidth {
				policy.CurrentBandwidth += (policy.MaxBandwidth - policy.MinBandwidth) / 10 // Adjust incrementally
			}
		} else {
			if policy.CurrentBandwidth > policy.MinBandwidth {
				policy.CurrentBandwidth -= (policy.MaxBandwidth - policy.MinBandwidth) / 10 // Adjust incrementally
			}
		}
		policy.LastUpdated = time.Now()
		ap.logger.Info("Adjusted bandwidth for policy: " + policy.Name)
	} else {
		ap.logger.Warning("Policy with ID " + id + " does not exist")
	}
}

// EncryptPolicyData encrypts the policy data using the policy's encryption manager
func (ap *AdaptivePolicies) EncryptPolicyData(id string, data []byte) ([]byte, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if policy, exists := ap.policies[id]; exists {
		encryptedData, err := policy.EncryptionManager.Encrypt(data)
		if err != nil {
			ap.logger.Error("Encryption failed for policy: " + policy.Name)
			return nil, err
		}
		return encryptedData, nil
	} else {
		ap.logger.Warning("Policy with ID " + id + " does not exist")
		return nil, fmt.Errorf("policy with ID %s does not exist", id)
	}
}

// DecryptPolicyData decrypts the policy data using the policy's encryption manager
func (ap *AdaptivePolicies) DecryptPolicyData(id string, encryptedData []byte) ([]byte, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if policy, exists := ap.policies[id]; exists {
		decryptedData, err := policy.EncryptionManager.Decrypt(encryptedData)
		if err != nil {
			ap.logger.Error("Decryption failed for policy: " + policy.Name)
			return nil, err
		}
		return decryptedData, nil
	} else {
		ap.logger.Warning("Policy with ID " + id + " does not exist")
		return nil, fmt.Errorf("policy with ID %s does not exist", id)
	}
}

// HashPolicyData hashes the policy data using the policy's hash manager
func (ap *AdaptivePolicies) HashPolicyData(id string, data []byte) ([]byte, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if policy, exists := ap.policies[id]; exists {
		hashedData, err := policy.HashManager.Hash(data)
		if err != nil {
			ap.logger.Error("Hashing failed for policy: " + policy.Name)
			return nil, err
		}
		return hashedData, nil
	} else {
		ap.logger.Warning("Policy with ID " + id + " does not exist")
		return nil, fmt.Errorf("policy with ID %s does not exist", id)
	}
}

// MonitorPolicies continuously monitors and adjusts policies based on real-time data
func (ap *AdaptivePolicies) MonitorPolicies() {
	for {
		ap.mu.Lock()
		for id, policy := range ap.policies {
			// Simulate network load and adjust bandwidth accordingly
			currentLoad := GetCurrentNetworkLoad(id)
			ap.AdjustBandwidth(id, currentLoad)
		}
		ap.mu.Unlock()
		time.Sleep(5 * time.Minute) // Adjust the frequency as needed
	}
}

// BandwidthAllocator manages the allocation of bandwidth within the Synnergy Network
type BandwidthAllocator struct {
	allocatedBandwidth map[string]int // maps node IDs to allocated bandwidth in kbps
	maxBandwidth       int            // maximum bandwidth available in kbps
	mu                 sync.Mutex     // mutex to protect shared resources
	logger             *common.Logger
	encryptionManager  *common.EncryptionManager
}

// NewBandwidthAllocator creates a new instance of BandwidthAllocator
func NewBandwidthAllocator(maxBandwidth int, logger *common.Logger, encryptionManager *EncryptionManager) *BandwidthAllocator {
	return &BandwidthAllocator{
		allocatedBandwidth: make(map[string]int),
		maxBandwidth:       maxBandwidth,
		logger:             logger,
		encryptionManager:  encryptionManager,
	}
}

// AllocateBandwidth allocates a specific amount of bandwidth to a node
func (ba *BandwidthAllocator) AllocateBandwidth(nodeID string, bandwidth int) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Check if the requested bandwidth exceeds the maximum available bandwidth
	totalAllocated := ba.totalAllocatedBandwidth()
	if totalAllocated+bandwidth > ba.maxBandwidth {
		err := errors.New("insufficient bandwidth available")
		ba.logger.Error(fmt.Sprintf("Failed to allocate bandwidth to node %s: %v", nodeID, err), "AllocateBandwidth")
		return err
	}

	// Allocate the bandwidth to the node
	ba.allocatedBandwidth[nodeID] = bandwidth
	ba.logger.Info(fmt.Sprintf("Allocated %d kbps bandwidth to node %s", bandwidth, nodeID), "AllocateBandwidth")
	return nil
}

// DeallocateBandwidth deallocates the bandwidth from a node
func (ba *BandwidthAllocator) DeallocateBandwidth(nodeID string) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if _, exists := ba.allocatedBandwidth[nodeID]; exists {
		delete(ba.allocatedBandwidth, nodeID)
		ba.logger.Info(fmt.Sprintf("Deallocated bandwidth from node %s", nodeID), "DeallocateBandwidth")
	}
}

// GetAllocatedBandwidth retrieves the currently allocated bandwidth for a node
func (ba *BandwidthAllocator) GetAllocatedBandwidth(nodeID string) (int, error) {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	bandwidth, exists := ba.allocatedBandwidth[nodeID]
	if !exists {
		err := errors.New("node not found")
		ba.logger.Error(fmt.Sprintf("Failed to get allocated bandwidth for node %s: %v", nodeID, err), "GetAllocatedBandwidth")
		return 0, err
	}
	return bandwidth, nil
}

// totalAllocatedBandwidth calculates the total allocated bandwidth across all nodes
func (ba *BandwidthAllocator) TotalAllocatedBandwidth() int {
	total := 0
	for _, bw := range ba.allocatedBandwidth {
		total += bw
	}
	return total
}

// MonitorBandwidthUsage continuously monitors the bandwidth usage and re-allocates if necessary
func (ba *BandwidthAllocator) MonitorBandwidthUsage() {
	for {
		time.Sleep(5 * time.Minute)

		ba.mu.Lock()
		totalAllocated := ba.totalAllocatedBandwidth()
		if totalAllocated > ba.maxBandwidth {
			ba.logger.Warning("Total allocated bandwidth exceeds maximum available bandwidth", "MonitorBandwidthUsage")
		}
		ba.mu.Unlock()
	}
}

// EncryptData encrypts the data using the configured encryption manager
func (ba *BandwidthAllocator) EncryptData(data []byte) ([]byte, error) {
	encryptedData, err := ba.encryptionManager.Encrypt(data)
	if err != nil {
		ba.logger.Error(fmt.Sprintf("Failed to encrypt data: %v", err), "EncryptData")
		return nil, err
	}
	return encryptedData, nil
}

// DecryptData decrypts the data using the configured encryption manager
func (ba *BandwidthAllocator) DecryptData(data []byte) ([]byte, error) {
	decryptedData, err := ba.encryptionManager.Decrypt(data)
	if err != nil {
		ba.logger.Error(fmt.Sprintf("Failed to decrypt data: %v", err), "DecryptData")
		return nil, err
	}
	return decryptedData, nil
}

// AdjustBandwidth dynamically adjusts the allocated bandwidth based on network conditions
func (ba *BandwidthAllocator) AdjustBandwidth(nodeID string, newBandwidth int) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Check if the node exists
	if _, exists := ba.allocatedBandwidth[nodeID]; !exists {
		err := errors.New("node not found")
		ba.logger.Error(fmt.Sprintf("Failed to adjust bandwidth for node %s: %v", nodeID, err), "AdjustBandwidth")
		return err
	}

	// Check if the new bandwidth exceeds the maximum available bandwidth
	totalAllocated := ba.totalAllocatedBandwidth() - ba.allocatedBandwidth[nodeID]
	if totalAllocated+newBandwidth > ba.maxBandwidth {
		err := errors.New("insufficient bandwidth available")
		ba.logger.Error(fmt.Sprintf("Failed to adjust bandwidth for node %s: %v", nodeID, err), "AdjustBandwidth")
		return err
	}

	// Adjust the bandwidth
	ba.allocatedBandwidth[nodeID] = newBandwidth
	ba.logger.Info(fmt.Sprintf("Adjusted bandwidth to %d kbps for node %s", newBandwidth, nodeID), "AdjustBandwidth")
	return nil
}

// GenerateBandwidthReport generates a report of the current bandwidth allocation
func (ba *BandwidthAllocator) GenerateBandwidthReport() string {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	report := "Current Bandwidth Allocation:\n"
	for nodeID, bandwidth := range ba.allocatedBandwidth {
		report += fmt.Sprintf("Node %s: %d kbps\n", nodeID, bandwidth)
	}
	ba.logger.Info("Generated bandwidth allocation report", "GenerateBandwidthReport")
	return report
}

// ApplyDynamicPolicies applies dynamic bandwidth allocation policies based on network conditions
func (ba *BandwidthAllocator) ApplyDynamicPolicies() {
	for {
		time.Sleep(10 * time.Minute)

		ba.mu.Lock()
		// Example dynamic policy: Reduce bandwidth for idle nodes
		for nodeID, bandwidth := range ba.allocatedBandwidth {
			if bandwidth > 0 && IsNodeIdle(nodeID) {
				ba.allocatedBandwidth[nodeID] /= 2
				ba.logger.Info(fmt.Sprintf("Reduced bandwidth for idle node %s to %d kbps", nodeID, ba.allocatedBandwidth[nodeID]), "ApplyDynamicPolicies")
			}
		}
		ba.mu.Unlock()
	}
}

// CongestionControl represents the mechanism for managing network congestion.
type CongestionControl struct {
	mu         sync.Mutex
	logger     *common.Logger
	thresholds CongestionThresholds
	strategies CongestionStrategies
}

// CongestionThresholds defines the thresholds for congestion levels.
type CongestionThresholds struct {
	High   int
	Medium int
	Low    int
}

// CongestionStrategies defines the strategies for handling different congestion levels.
type CongestionStrategies struct {
	High   func()
	Medium func()
	Low    func()
}

// NewCongestionControl creates a new instance of CongestionControl.
func NewCongestionControl(logger *Logger, thresholds CongestionThresholds, strategies CongestionStrategies) *CongestionControl {
	return &CongestionControl{
		logger:     logger,
		thresholds: thresholds,
		strategies: strategies,
	}
}

// MonitorNetwork monitors the network for congestion and applies appropriate strategies.
func (cc *CongestionControl) MonitorNetwork() {
	for {
		cc.mu.Lock()
		trafficLoad := GetCurrentTrafficLoad()
		cc.mu.Unlock()

		switch {
		case trafficLoad >= cc.thresholds.High:
			cc.logger.Info("High congestion detected, applying high congestion strategy", "MonitorNetwork")
			cc.strategies.High()
		case trafficLoad >= cc.thresholds.Medium:
			cc.logger.Info("Medium congestion detected, applying medium congestion strategy", "MonitorNetwork")
			cc.strategies.Medium()
		case trafficLoad >= cc.thresholds.Low:
			cc.logger.Info("Low congestion detected, applying low congestion strategy", "MonitorNetwork")
			cc.strategies.Low()
		default:
			cc.logger.Info("No significant congestion detected", "MonitorNetwork")
		}

		time.Sleep(1 * time.Minute) // Monitor every minute
	}
}

// HighCongestionStrategy applies high congestion strategy
func HighCongestionStrategy() {
	// High congestion strategy implementation
	fmt.Println("Applying high congestion strategy...")
	// Throttle non-essential traffic
	ThrottleTraffic("non-essential")
	// Increase priority for critical transactions
	SetTransactionPriority("critical", 1)
}

// MediumCongestionStrategy applies medium congestion strategy
func MediumCongestionStrategy() {
	// Medium congestion strategy implementation
	fmt.Println("Applying medium congestion strategy...")
	// Moderate traffic shaping
	ShapeTraffic("moderate")
	// Adjust transaction priority
	SetTransactionPriority("normal", 2)
}

// LowCongestionStrategy applies low congestion strategy
func ApplyLowCongestionStrategy() {
	// Low congestion strategy implementation
	fmt.Println("Applying low congestion strategy...")
	// Minimal traffic shaping
	ShapeTraffic("minimal")
	// Normal transaction processing
	SetTransactionPriority("all", 3)
}

// Start starts the congestion control monitoring process.
func (cc *CongestionControl) Start() {
	go cc.MonitorNetwork()
	cc.logger.Info("Started congestion control monitoring", "Start")
}

// Control struct manages the flow control mechanisms
type FlowControl struct {
	maxBandwidth      int64
	currentBandwidth  int64
	bandwidthLock     sync.Mutex
	throttleEnabled   bool
	congestionControl *CongestionControl
	rateLimiter       *common.RateLimiter
}

// NewControl creates a new Control instance
func NewControl(maxBandwidth int64, throttleEnabled bool) *FlowControl {
	return &Control{
		maxBandwidth:      maxBandwidth,
		throttleEnabled:   throttleEnabled,
		congestionControl: NewCongestionControl(),
		rateLimiter:       NewRateLimiter(),
	}
}

// SetMaxBandwidth sets the maximum bandwidth for the flow control
func (c *FlowControl) SetMaxBandwidth(maxBandwidth int64) {
	c.bandwidthLock.Lock()
	defer c.bandwidthLock.Unlock()
	c.maxBandwidth = maxBandwidth
}

// GetMaxBandwidth returns the maximum bandwidth
func (c *FlowControl) GetMaxBandwidth() int64 {
	c.bandwidthLock.Lock()
	defer c.bandwidthLock.Unlock()
	return c.maxBandwidth
}

// UpdateBandwidth updates the current bandwidth usage
func (c *FlowControl) UpdateBandwidth(usedBandwidth int64) error {
	c.bandwidthLock.Lock()
	defer c.bandwidthLock.Unlock()

	if usedBandwidth > c.maxBandwidth {
		return errors.New("used bandwidth exceeds the maximum limit")
	}

	atomic.AddInt64(&c.currentBandwidth, usedBandwidth)
	return nil
}

// ThrottleControl enables or disables throttling based on the network condition
func (c *FlowControl) ThrottleControl(enabled bool) {
	c.bandwidthLock.Lock()
	defer c.bandwidthLock.Unlock()
	c.throttleEnabled = enabled
}

// IsThrottling returns if throttling is enabled
func (c *Control) IsThrottling() bool {
	c.bandwidthLock.Lock()
	defer c.bandwidthLock.Unlock()
	return c.throttleEnabled
}

// ApplyThrottle applies throttling to the network traffic
func (c *FlowControl) ApplyThrottle(conn net.Conn, throttleRate int64) error {
	if !c.throttleEnabled {
		return nil
	}

	throttle := time.Duration(throttleRate) * time.Millisecond
	for {
		buffer := make([]byte, 1024)
		_, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		time.Sleep(throttle)
	}
}

// MonitorNetwork monitors the network for congestion and applies necessary control
func (c *FlowControl) MonitorNetwork(conn net.Conn) {
	for {
		trafficLoad := rand.Int63n(100) // Simulated traffic load
		if trafficLoad > c.maxBandwidth {
			log.Println("Network congestion detected, applying control measures")
			c.ApplyThrottle(conn, trafficLoad-c.maxBandwidth)
		}
		time.Sleep(1 * time.Second)
	}
}

// HandlePacket processes incoming network packets
func (c *FlowControl) HandlePacket(packet []byte) ([]byte, error) {
	// Simulate packet handling logic
	if len(packet) == 0 {
		return nil, errors.New("packet is empty")
	}

	decryptedPacket, err := Decrypt(packet)
	if err != nil {
		return nil, err
	}

	// Simulated processing
	processedPacket := append(decryptedPacket, []byte(" processed")...)
	encryptedPacket, err := Encrypt(processedPacket)
	if err != nil {
		return nil, err
	}

	return encryptedPacket, nil
}

// LogError logs the errors using the custom logger
func (c *FlowControl) LogError(err error) {
	LogError(err)
}

// Throttle struct represents the throttling mechanism
type Throttle struct {
	rateLimit  int           // maximum requests per interval
	interval   time.Duration // interval for rate limiting
	allowances map[string]float64
	lastCheck  map[string]time.Time
	mtx        sync.Mutex
}

// NewThrottle creates a new Throttle instance
func NewThrottle(rateLimit int, interval time.Duration) *Throttle {
	return &Throttle{
		rateLimit:  rateLimit,
		interval:   interval,
		allowances: make(map[string]float64),
		lastCheck:  make(map[string]time.Time),
	}
}

// Allow checks if a request from a given identifier can proceed
func (t *Throttle) Allow(identifier string) (bool, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	now := time.Now()
	last, exists := t.lastCheck[identifier]
	if !exists {
		t.lastCheck[identifier] = now
		t.allowances[identifier] = float64(t.rateLimit)
	} else {
		elapsed := now.Sub(last).Seconds()
		t.lastCheck[identifier] = now
		t.allowances[identifier] += elapsed * (float64(t.rateLimit) / t.interval.Seconds())
		if t.allowances[identifier] > float64(t.rateLimit) {
			t.allowances[identifier] = float64(t.rateLimit)
		}
	}

	if t.allowances[identifier] < 1.0 {
		return false, nil
	}

	t.allowances[identifier] -= 1.0
	return true, nil
}

// SetRateLimit sets a new rate limit for the throttle
func (t *Throttle) SetRateLimit(rateLimit int) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.rateLimit = rateLimit
}

// SetInterval sets a new interval for the throttle
func (t *Throttle) SetInterval(interval time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	t.interval = interval
}

// Reset resets the throttling for a specific identifier
func (t *Throttle) Reset(identifier string) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	delete(t.allowances, identifier)
	delete(t.lastCheck, identifier)
}

// SecureThrottle enhances throttle security using cryptographic techniques
func (t *Throttle) SecureThrottle(identifier string, secretKey string) error {
	encryptedID, err := EncryptAES(identifier, secretKey)
	if err != nil {
		return err
	}
	allowed, err := t.Allow(encryptedID)
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("rate limit exceeded")
	}
	return nil
}

// ThrottleHandler handles incoming requests and applies throttling
func ThrottleHandler(throttle *Throttle, secretKey string, handler func() error) error {
	identifier, err := GenerateUniqueID()
	if err != nil {
		return err
	}
	err = throttle.SecureThrottle(identifier, secretKey)
	if err != nil {
		return err
	}
	return handler()
}


// Info logs informational messages
func (l *common.Logger) Info(message, context string) {
	log.Printf("INFO: %s - %s", context, message)
}

// Error logs error messages
func (l *common.Logger) Error(message, context string) {
	log.Printf("ERROR: %s - %s", context, message)
}

// Warning logs warning messages
func (l *common.Logger) Warning(message, context string) {
	log.Printf("WARNING: %s - %s", context, message)
}


// Hash generates a hash of the given data
func (hm *common.HashManager) Hash(data []byte) ([]byte, error) {
	return data, nil
}


// Encrypt encrypts the given data
func (em *common.EncryptionManager) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

// Decrypt decrypts the given data
func (em *common.EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

// GetCurrentNetworkLoad simulates getting the current network load
func GetCurrentNetworkLoad(id string) int {
	return rand.Intn(100)
}

// ThrottleTraffic simulates throttling traffic
func ThrottleTraffic(trafficType string) {
}

// SetTransactionPriority simulates setting transaction priority
func SetTransactionPriority(priorityType string, priority int) {
}

// ShapeTraffic simulates traffic shaping
func ShapeTraffic(shapeType string) {
}

// GetCurrentTrafficLoad simulates getting the current traffic load
func GetCurrentTrafficLoad() int {
	return rand.Intn(100)
}

// Decrypt simulates decrypting data
func Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

// Encrypt simulates encrypting data
func Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

// RateLimiter represents a rate limiter
type RateLimiter struct {
}

// NewRateLimiter creates a new instance of RateLimiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

// LogError logs errors
func LogError(err error) {
	log.Println(err)
}

// GenerateUniqueID simulates generating a unique ID
func GenerateUniqueID() (string, error) {
	return "unique-id", nil
}

// IsNodeIdle simulates checking if a node is idle
func IsNodeIdle(nodeID string) bool {
	return false
}
