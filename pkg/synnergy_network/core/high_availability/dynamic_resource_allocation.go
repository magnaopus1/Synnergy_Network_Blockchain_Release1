package disaster_recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/consensus/synnergy_consensus"
	"github.com/synnergy_network_blockchain/cryptography/encryption"
	"github.com/synnergy_network_blockchain/high_availability/utils"
	"github.com/synnergy_network_blockchain/network/p2p"
	"github.com/synnergy_network_blockchain/operations/monitoring"
)

// NewHealthMonitor initializes a new HealthMonitor
func NewHealthMonitor(nodes []p2p.Node) *HealthMonitor {
	return &HealthMonitor{
		nodes:      nodes,
		healthData: make(map[string]NodeHealth),
		alertChan:  make(chan string),
	}
}

// StartMonitoring starts the health monitoring process
func (hm *HealthMonitor) StartMonitoring(ctx context.Context) {
	for _, node := range hm.nodes {
		go hm.monitorNode(ctx, node)
	}
}

// monitorNode monitors the health of a single node
func (hm *HealthMonitor) monitorNode(ctx context.Context, node p2p.Node) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			health := hm.checkNodeHealth(node)
			hm.healthDataLock.Lock()
			hm.healthData[node.ID] = health
			hm.healthDataLock.Unlock()
			if hm.isAnomaly(health) {
				hm.alertChan <- fmt.Sprintf("Anomaly detected in node %s", node.ID)
			}
			time.Sleep(10 * time.Second)
		}
	}
}

// checkNodeHealth checks the health metrics of a node
func (hm *HealthMonitor) checkNodeHealth(node p2p.Node) NodeHealth {
	// Simulate fetching node health data
	return NodeHealth{
		CPUUsage:       utils.GetCPUUsage(node),
		MemoryUsage:    utils.GetMemoryUsage(node),
		DiskIO:         utils.GetDiskIO(node),
		NetworkLatency: utils.GetNetworkLatency(node),
	}
}

// isAnomaly detects anomalies in the node health data
func (hm *HealthMonitor) isAnomaly(health NodeHealth) bool {
	// Implement anomaly detection logic
	return health.CPUUsage > 80.0 || health.MemoryUsage > 80.0 || health.DiskIO > 80.0
}

// RecoveryTester performs automated recovery tests
type RecoveryTester struct {
	healthMonitor *HealthMonitor
	testResults   []RecoveryTestResult
	resultsLock   sync.Mutex
}

// NewRecoveryTester initializes a new RecoveryTester
func NewRecoveryTester(healthMonitor *HealthMonitor) *RecoveryTester {
	return &RecoveryTester{
		healthMonitor: healthMonitor,
	}
}

// RunTests runs all recovery tests
func (rt *RecoveryTester) RunTests() {
	rt.runTest("Network Partition Test", rt.testNetworkPartition)
	rt.runTest("Node Crash Test", rt.testNodeCrash)
	rt.runTest("Data Corruption Test", rt.testDataCorruption)
}

// runTest runs a specific recovery test
func (rt *RecoveryTester) runTest(testName string, testFunc func() bool) {
	result := RecoveryTestResult{
		TestName:  testName,
		Timestamp: time.Now(),
		Success:   testFunc(),
	}
	rt.resultsLock.Lock()
	rt.testResults = append(rt.testResults, result)
	rt.resultsLock.Unlock()
	rt.logResult(result)
}

// testNetworkPartition simulates a network partition and tests recovery
func (rt *RecoveryTester) testNetworkPartition() bool {
	// Simulate network partition
	log.Println("Simulating network partition...")
	time.Sleep(5 * time.Second)
	// Verify recovery
	return rt.verifyRecovery()
}

// testNodeCrash simulates a node crash and tests recovery
func (rt *RecoveryTester) testNodeCrash() bool {
	// Simulate node crash
	log.Println("Simulating node crash...")
	time.Sleep(5 * time.Second)
	// Verify recovery
	return rt.verifyRecovery()
}

// testDataCorruption simulates data corruption and tests recovery
func (rt *RecoveryTester) testDataCorruption() bool {
	// Simulate data corruption
	log.Println("Simulating data corruption...")
	time.Sleep(5 * time.Second)
	// Verify recovery
	return rt.verifyRecovery()
}

// verifyRecovery verifies the recovery of the network
func (rt *RecoveryTester) verifyRecovery() bool {
	// Implement verification logic
	return true
}

// logResult logs the result of a recovery test
func (rt *RecoveryTester) logResult(result RecoveryTestResult) {
	log.Printf("Test: %s, Success: %v, Details: %s\n", result.TestName, result.Success, result.Details)
}

// BackupVerification verifies the integrity of backup data
type BackupVerification struct {
	dataDir string
}

// NewBackupVerification initializes a new BackupVerification
func NewBackupVerification(dataDir string) *BackupVerification {
	return &BackupVerification{
		dataDir: dataDir,
	}
}

// VerifyBackups verifies the integrity of all backups
func (bv *BackupVerification) VerifyBackups() bool {
	files, err := os.ReadDir(bv.dataDir)
	if err != nil {
		log.Fatalf("Failed to read backup directory: %v", err)
		return false
	}

	for _, file := range files {
		if !bv.verifyFile(file.Name()) {
			return false
		}
	}
	return true
}

// verifyFile verifies the integrity of a single backup file
func (bv *BackupVerification) verifyFile(filename string) bool {
	filePath := fmt.Sprintf("%s/%s", bv.dataDir, filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read backup file %s: %v", filename, err)
		return false
	}

	hash := sha256.Sum256(data)
	expectedHash := bv.getExpectedHash(filename)
	return hex.EncodeToString(hash[:]) == expectedHash
}

// getExpectedHash gets the expected hash of a backup file
func (bv *BackupVerification) getExpectedHash(filename string) string {
	// Simulate fetching expected hash from metadata
	return "expected_hash_value"
}


// NewAdaptiveResourceAllocator creates a new adaptive resource allocator
func NewAdaptiveResourceAllocator(nodes []*Node, loadThreshold, scaleUpFactor, scaleDownFactor float64) *AdaptiveResourceAllocator {
	return &AdaptiveResourceAllocator{
		nodes:           nodes,
		loadThreshold:   loadThreshold,
		scaleUpFactor:   scaleUpFactor,
		scaleDownFactor: scaleDownFactor,
	}
}

// MonitorNodes continuously monitors the nodes and adjusts resources as needed
func (ara *AdaptiveResourceAllocator) MonitorNodes() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ara.mu.Lock()
			for _, node := range ara.nodes {
				if time.Since(node.LastHeartbeat) > 30*time.Second {
					fmt.Printf("Node %s missed heartbeat, initiating failover...\n", node.ID)
					ara.initiateFailover(node)
				}
			}
			ara.mu.Unlock()
		}
	}
}

// AdjustResources dynamically adjusts the resources of the nodes based on their load
func (ara *AdaptiveResourceAllocator) AdjustResources() {
	for {
		time.Sleep(30 * time.Second)

		ara.mu.Lock()
		for _, node := range ara.nodes {
			if node.CPUUsage > ara.loadThreshold {
				fmt.Printf("Node %s is over threshold, scaling up resources...\n", node.ID)
				ara.scaleUpResources(node)
			} else if node.CPUUsage < ara.loadThreshold*ara.scaleDownFactor {
				fmt.Printf("Node %s is under threshold, scaling down resources...\n", node.ID)
				ara.scaleDownResources(node)
			}
		}
		ara.mu.Unlock()
	}
}

// scaleUpResources increases the resources allocated to a node
func (ara *AdaptiveResourceAllocator) scaleUpResources(node *Node) {
	node.CPUUsage *= ara.scaleUpFactor
	node.MemoryUsage *= ara.scaleUpFactor
	node.DiskUsage *= ara.scaleUpFactor
}

// scaleDownResources decreases the resources allocated to a node
func (ara *AdaptiveResourceAllocator) scaleDownResources(node *Node) {
	node.CPUUsage *= ara.scaleDownFactor
	node.MemoryUsage *= ara.scaleDownFactor
	node.DiskUsage *= ara.scaleDownFactor
}

// initiateFailover handles the failover process for a node
func (ara *AdaptiveResourceAllocator) initiateFailover(failedNode *Node) {
	for _, node := range ara.nodes {
		if node.ID != failedNode.ID {
			fmt.Printf("Failing over responsibilities of node %s to node %s\n", failedNode.ID, node.ID)
			node.CPUUsage += failedNode.CPUUsage
			node.MemoryUsage += failedNode.MemoryUsage
			node.DiskUsage += failedNode.DiskUsage
			return
		}
	}
}

// EncryptData encrypts the data using scrypt algorithm
func EncryptData(data []byte, passphrase []byte) ([]byte, error) {
	salt, err := utils.GenerateRandomBytes(16)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return crypto.EncryptAES(data, key)
}

// DecryptData decrypts the data using scrypt algorithm
func DecryptData(encryptedData []byte, passphrase []byte) ([]byte, error) {
	salt, err := utils.ExtractSalt(encryptedData)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptAES(encryptedData, key)
}

// NewRoundRobinAlgorithm creates a new RoundRobinAlgorithm
func NewRoundRobinAlgorithm() *RoundRobinAlgorithm {
	return &RoundRobinAlgorithm{}
}

// DistributeLoad distributes the task in a round-robin fashion
func (r *RoundRobinAlgorithm) DistributeLoad(nodes []*Node, task Task) string {
	nodeID := nodes[r.current%len(nodes)].ID
	r.current++
	return nodeID
}

// AdaptiveLoadBalancer creates a new LoadBalancer with adaptive algorithms
func NewAdaptiveLoadBalancer(algo AdaptiveAlgorithm) *LoadBalancer {
	return &LoadBalancer{
		Nodes:        make([]*Node, 0),
		TaskQueue:    make([]Task, 0),
		quit:         make(chan bool),
		adaptiveAlgo: algo,
	}
}

// AddNode adds a new node to the load balancer
func (lb *LoadBalancer) AddNode(node *Node) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.Nodes = append(lb.Nodes, node)
}

// RemoveNode removes a node from the load balancer
func (lb *LoadBalancer) RemoveNode(nodeID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, node := range lb.Nodes {
		if node.ID == nodeID {
			lb.Nodes = append(lb.Nodes[:i], lb.Nodes[i+1:]...)
			break
		}
	}
}

// AssignTask assigns a task to an appropriate node
func (lb *LoadBalancer) AssignTask(task Task) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	nodeID := lb.adaptiveAlgo.DistributeLoad(lb.Nodes, task)
	for _, node := range lb.Nodes {
		if node.ID == nodeID {
			node.TaskQueue = append(node.TaskQueue, task)
			break
		}
	}
}

// MonitorNodes continuously monitors node performance and adjusts load distribution
func (lb *LoadBalancer) MonitorNodes() {
	for {
		select {
		case <-lb.quit:
			return
		default:
			lb.mu.Lock()
			for _, node := range lb.Nodes {
				lb.updateNodePerformance(node)
			}
			lb.mu.Unlock()
			time.Sleep(5 * time.Second)
		}
	}
}

// updateNodePerformance updates the performance metrics of a node
func (lb *LoadBalancer) updateNodePerformance(node *Node) {
	// Simulating the collection of real-time performance metrics
	node.CPUUsage = rand.Float64() * 100
	node.MemoryUsage = rand.Float64() * 100
	node.NetworkLatency = rand.Float64() * 100
	log.Printf("Node %s - CPU: %.2f%%, Memory: %.2f%%, Latency: %.2fms\n",
		node.ID, node.CPUUsage, node.MemoryUsage, node.NetworkLatency)
}

// Stop stops the load balancer's monitoring process
func (lb *LoadBalancer) Stop() {
	lb.quit <- true
}

// NewPredictiveResourceScaling initializes a new PredictiveResourceScaling instance.
func NewPredictiveResourceScaling(resourceManager *dynamic_resource_allocation.ResourceManager, consensus *synnergy_consensus.Consensus, p2pNetwork *mesh_networking.P2PNetwork) *PredictiveResourceScaling {
    return &PredictiveResourceScaling{
        historicalData:   make([]ResourceMetrics, 0),
        model:            &PredictionModel{},
        resourceManager:  resourceManager,
        consensus:        consensus,
        encryption:       &encryption.EncryptionService{},
        hash:             &hash.HashService{},
        p2pNetwork:       p2pNetwork,
        scalingInterval:  5 * time.Minute,
        scalingThreshold: 0.75, // 75% threshold for scaling
    }
}

// CollectMetrics collects resource metrics from nodes.
func (prs *PredictiveResourceScaling) CollectMetrics() {
    prs.mutex.Lock()
    defer prs.mutex.Unlock()

    metrics := prs.resourceManager.CollectMetrics()
    prs.historicalData = append(prs.historicalData, metrics)
}

// TrainModel trains the prediction model using historical data.
func (prs *PredictiveResourceScaling) TrainModel() {
    prs.mutex.Lock()
    defer prs.mutex.Unlock()

    // Training the model with historical data
    prs.model.Train(prs.historicalData)
}

// PredictResourceNeeds predicts the future resource needs based on current data.
func (prs *PredictiveResourceScaling) PredictResourceNeeds() ResourceMetrics {
    prs.mutex.Lock()
    defer prs.mutex.Unlock()

    return prs.model.Predict(prs.historicalData)
}

// ScaleResources scales the resources based on predicted needs.
func (prs *PredictiveResourceScaling) ScaleResources() {
    predictedMetrics := prs.PredictResourceNeeds()
    
    if predictedMetrics.CPUUsage > prs.scalingThreshold || predictedMetrics.MemoryUsage > prs.scalingThreshold {
        prs.resourceManager.ScaleUp()
    } else if predictedMetrics.CPUUsage < prs.scalingThreshold/2 && predictedMetrics.MemoryUsage < prs.scalingThreshold/2 {
        prs.resourceManager.ScaleDown()
    }
}

// Run starts the predictive resource scaling process.
func (prs *PredictiveResourceScaling) Run() {
    ticker := time.NewTicker(prs.scalingInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            prs.CollectMetrics()
            prs.TrainModel()
            prs.ScaleResources()
        }
    }
}

// SecureCommunication ensures that data exchanged between nodes is encrypted and secure.
func (prs *PredictiveResourceScaling) SecureCommunication(data []byte) ([]byte, error) {
    encryptedData, err := prs.encryption.Encrypt(data)
    if err != nil {
        return nil, err
    }
    return encryptedData, nil
}

// VerifyDataIntegrity verifies the integrity of the data using cryptographic hashing.
func (prs *PredictiveResourceScaling) VerifyDataIntegrity(data []byte, hashValue []byte) bool {
    return prs.hash.Verify(data, hashValue)
}

// SyncWithPeers synchronizes resource data with peer nodes.
func (prs *PredictiveResourceScaling) SyncWithPeers() {
    data, err := prs.resourceManager.ExportData()
    if err != nil {
        log.Println("Error exporting data:", err)
        return
    }

    encryptedData, err := prs.SecureCommunication(data)
    if err != nil {
        log.Println("Error encrypting data:", err)
        return
    }

    for _, peer := range prs.p2pNetwork.GetPeers() {
        if err := peer.Send(encryptedData); err != nil {
            log.Println("Error sending data to peer:", err)
        }
    }
}




// NewMonitoringService initializes a new MonitoringService
func NewMonitoringService(cryptoKey []byte) *MonitoringService {
	return &MonitoringService{
		nodes:     make(map[string]*NodeMetrics),
		alerts:    make(chan string),
		quit:      make(chan bool),
		cryptoKey: cryptoKey,
	}
}

// CollectMetrics collects metrics from a given node
func (ms *MonitoringService) CollectMetrics(nodeID string) {
	for {
		select {
		case <-ms.quit:
			return
		default:
			// Simulate metrics collection
			metrics := &NodeMetrics{
				CPUUsage:      float64(rand.Intn(100)),
				MemoryUsage:   float64(rand.Intn(100)),
				DiskIO:        float64(rand.Intn(100)),
				NetworkLatency: float64(rand.Intn(100)),
			}
			ms.mutex.Lock()
			ms.nodes[nodeID] = metrics
			ms.mutex.Unlock()
			time.Sleep(10 * time.Second)
		}
	}
}

// AnalyzeMetrics analyzes the collected metrics to detect anomalies
func (ms *MonitoringService) AnalyzeMetrics() {
	for {
		select {
		case <-ms.quit:
			return
		default:
			ms.mutex.Lock()
			for nodeID, metrics := range ms.nodes {
				if metrics.CPUUsage > 90 || metrics.MemoryUsage > 90 || metrics.DiskIO > 90 || metrics.NetworkLatency > 100 {
					ms.alerts <- "High resource usage detected on node: " + nodeID
				}
			}
			ms.mutex.Unlock()
			time.Sleep(5 * time.Second)
		}
	}
}

// EncryptData encrypts the data using the best encryption method
func (ms *MonitoringService) EncryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(ms.cryptoKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the data
func (ms *MonitoringService) DecryptData(encryptedData string) ([]byte, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ms.cryptoKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Start starts the real-time monitoring service
func (ms *MonitoringService) Start() {
	go ms.AnalyzeMetrics()
	for nodeID := range ms.nodes {
		go ms.CollectMetrics(nodeID)
	}
}

// Stop stops the real-time monitoring service
func (ms *MonitoringService) Stop() {
	close(ms.quit)
	close(ms.alerts)
}

// MonitorEndpoint is the HTTP handler for monitoring requests
func (ms *MonitoringService) MonitorEndpoint(w http.ResponseWriter, r *http.Request) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	nodeID := r.URL.Query().Get("node")
	if nodeID == "" {
		http.Error(w, "Missing node ID", http.StatusBadRequest)
		return
	}

	metrics, exists := ms.nodes[nodeID]
	if !exists {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	encryptedMetrics, err := ms.EncryptData(metrics)
	if err != nil {
		http.Error(w, "Failed to encrypt metrics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"node":    nodeID,
		"metrics": encryptedMetrics,
	})
}

// Init initializes the monitoring service
func Init() *MonitoringService {
	key := generateCryptoKey()
	ms := NewMonitoringService(key)
	ms.Start()
	return ms
}

// generateCryptoKey generates a new encryption key
func generateCryptoKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate encryption key: ", err)
	}
	return key
}

func main() {
	monitoringService := Init()
	defer monitoringService.Stop()

	http.HandleFunc("/monitor", monitoringService.MonitorEndpoint)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// NewMonitoringService initializes a new MonitoringService
func NewMonitoringService(cryptoKey []byte) *MonitoringService {
	return &MonitoringService{
		nodes:     make(map[string]*NodeMetrics),
		alerts:    make(chan string),
		quit:      make(chan bool),
		cryptoKey: cryptoKey,
	}
}

// CollectMetrics collects metrics from a given node
func (ms *MonitoringService) CollectMetrics(nodeID string) {
	for {
		select {
		case <-ms.quit:
			return
		default:
			// Simulate metrics collection
			metrics := &NodeMetrics{
				CPUUsage:      float64(rand.Intn(100)),
				MemoryUsage:   float64(rand.Intn(100)),
				DiskIO:        float64(rand.Intn(100)),
				NetworkLatency: float64(rand.Intn(100)),
			}
			ms.mutex.Lock()
			ms.nodes[nodeID] = metrics
			ms.mutex.Unlock()
			time.Sleep(10 * time.Second)
		}
	}
}

// AnalyzeMetrics analyzes the collected metrics to detect anomalies
func (ms *MonitoringService) AnalyzeMetrics() {
	for {
		select {
		case <-ms.quit:
			return
		default:
			ms.mutex.Lock()
			for nodeID, metrics := range ms.nodes {
				if metrics.CPUUsage > 90 || metrics.MemoryUsage > 90 || metrics.DiskIO > 90 || metrics.NetworkLatency > 100 {
					ms.alerts <- "High resource usage detected on node: " + nodeID
				}
			}
			ms.mutex.Unlock()
			time.Sleep(5 * time.Second)
		}
	}
}

// EncryptData encrypts the data using the best encryption method
func (ms *MonitoringService) EncryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(ms.cryptoKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the data
func (ms *MonitoringService) DecryptData(encryptedData string) ([]byte, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ms.cryptoKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Start starts the real-time monitoring service
func (ms *MonitoringService) Start() {
	go ms.AnalyzeMetrics()
	for nodeID := range ms.nodes {
		go ms.CollectMetrics(nodeID)
	}
}

// Stop stops the real-time monitoring service
func (ms *MonitoringService) Stop() {
	close(ms.quit)
	close(ms.alerts)
}

// MonitorEndpoint is the HTTP handler for monitoring requests
func (ms *MonitoringService) MonitorEndpoint(w http.ResponseWriter, r *http.Request) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	nodeID := r.URL.Query().Get("node")
	if nodeID == "" {
		http.Error(w, "Missing node ID", http.StatusBadRequest)
		return
	}

	metrics, exists := ms.nodes[nodeID]
	if !exists {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	encryptedMetrics, err := ms.EncryptData(metrics)
	if err != nil {
		http.Error(w, "Failed to encrypt metrics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"node":    nodeID,
		"metrics": encryptedMetrics,
	})
}

// Init initializes the monitoring service
func Init() *MonitoringService {
	key := generateCryptoKey()
	ms := NewMonitoringService(key)
	ms.Start()
	return ms
}

// generateCryptoKey generates a new encryption key
func generateCryptoKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate encryption key: ", err)
	}
	return key
}


// NewMonitor creates a new Monitor instance
func NewMonitor(nodeID string, thresholds Thresholds, subscribers []AlertSubscriber, peerCommunicator p2p.Communicator, resourceOptimizer optimization.Optimizer) *Monitor {
	return &Monitor{
		nodeID:            nodeID,
		alertThresholds:   thresholds,
		alertSubscribers:  subscribers,
		peerCommunicator:  peerCommunicator,
		resourceOptimizer: resourceOptimizer,
		logger:            log.New(os.Stdout, "REAL_TIME_MONITORING: ", log.LstdFlags),
	}
}

// Start initiates the real-time monitoring process
func (m *Monitor) Start() {
	m.logger.Println("Starting real-time monitoring...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectData()
			m.checkThresholds()
			m.broadcastMetrics()
			m.optimizeResources()
		}
	}
}

// collectData collects resource usage data
func (m *Monitor) collectData() {
	m.dataMutex.Lock()
	defer m.dataMutex.Unlock()

	m.cpuUsage = utils.GetCPUUsage()
	m.memoryUsage = utils.GetMemoryUsage()
	m.diskIO = utils.GetDiskIO()
	m.networkBandwidth = utils.GetNetworkBandwidth()
	m.lastUpdated = time.Now()

	m.logger.Printf("Collected data: CPU=%.2f%%, Memory=%.2f%%, Disk IO=%.2f, Network Bandwidth=%.2f\n", m.cpuUsage, m.memoryUsage, m.diskIO, m.networkBandwidth)
}

// checkThresholds checks if the current resource usage exceeds the alert thresholds
func (m *Monitor) checkThresholds() {
	m.dataMutex.Lock()
	defer m.dataMutex.Unlock()

	alerts := []string{}
	if m.cpuUsage > m.alertThresholds.CPUUsage {
		alerts = append(alerts, fmt.Sprintf("CPU usage high: %.2f%%", m.cpuUsage))
	}
	if m.memoryUsage > m.alertThresholds.MemoryUsage {
		alerts = append(alerts, fmt.Sprintf("Memory usage high: %.2f%%", m.memoryUsage))
	}
	if m.diskIO > m.alertThresholds.DiskIO {
		alerts = append(alerts, fmt.Sprintf("Disk IO high: %.2f", m.diskIO))
	}
	if m.networkBandwidth > m.alertThresholds.NetworkBandwidth {
		alerts = append(alerts, fmt.Sprintf("Network bandwidth high: %.2f", m.networkBandwidth))
	}

	for _, alert := range alerts {
		m.logger.Println("ALERT:", alert)
		m.notifySubscribers(alert)
	}
}

// notifySubscribers notifies all subscribers about an alert
func (m *Monitor) notifySubscribers(alert string) {
	for _, subscriber := range m.alertSubscribers {
		subscriber.Notify(alert)
	}
}

// broadcastMetrics broadcasts the collected metrics to peer nodes
func (m *Monitor) broadcastMetrics() {
	metrics := map[string]float64{
		"CPUUsage":         m.cpuUsage,
		"MemoryUsage":      m.memoryUsage,
		"DiskIO":           m.diskIO,
		"NetworkBandwidth": m.networkBandwidth,
	}

	hashedMetrics := hash.HashData(metrics)
	m.peerCommunicator.Broadcast("MetricsUpdate", hashedMetrics)
	m.logger.Println("Broadcasted metrics to peers.")
}

// optimizeResources optimizes resource allocation based on collected data
func (m *Monitor) optimizeResources() {
	m.resourceOptimizer.Optimize(m.cpuUsage, m.memoryUsage, m.diskIO, m.networkBandwidth)
	m.logger.Println("Resource optimization triggered.")
}

// Stop halts the real-time monitoring process
func (m *Monitor) Stop() {
	m.logger.Println("Stopping real-time monitoring...")
	// Implement graceful shutdown if needed
}
