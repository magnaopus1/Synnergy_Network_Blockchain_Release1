package storageallocation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type StorageAllocator struct {
	nodeStorageCapacities map[string]int
	allocatedStorage      map[string]int
	allocationLock        sync.Mutex
	storagePricing        float64
	redundancyFactor      int
	storageUsageHistory   map[string][]int
}

type RedundancyManager struct {
	redundancyLevel  int
	storageNodes     []StorageNode
	nodeLock         sync.Mutex
}

type StorageNode struct {
	ID          string
	TotalSpace  int64
	UsedSpace   int64
	LastUpdated time.Time
}

type ResourceManager struct {
	storageNodes       map[string]*StorageNode
	nodeLock           sync.RWMutex
	allocationStrategy AllocationStrategy
}

type AllocationStrategy interface {
	Allocate(storageNodes map[string]*StorageNode, fileSize int64) (string, error)
}

type SimpleAllocationStrategy struct{}

type DynamicPricingManager struct {
	storagePrices     map[string]float64
	priceLock         sync.Mutex
	usageStats        map[string]float64
	usageLock         sync.Mutex
	priceUpdateTicker *time.Ticker
}

type MultiTierStorage struct {
	hotStorage  *StorageTier
	coldStorage *StorageTier
	tierLock    sync.Mutex
}

type StorageTier struct {
	basePath string
	files    map[string]*StoredFile
	fileLock sync.RWMutex
}

type StoredFile struct {
	Data        []byte
	LastAccess  time.Time
	AccessCount int
}

type SecureStorageManager struct {
	encryptionKey []byte
	storage       map[string]string
	storageLock   sync.Mutex
}

type StorageManager struct {
	allocations      map[string]StorageAllocation
	allocationsMutex sync.Mutex
	pricingModel     *DynamicPricingModel
}

type StorageAllocation struct {
	NodeID    string
	Size      int64
	Timestamp time.Time
}

type DynamicPricingModel struct {
	BasePrice     float64
	CurrentPrice  float64
	PricingFactor float64
}

func NewStorageAllocator() *StorageAllocator {
	return &StorageAllocator{
		nodeStorageCapacities: make(map[string]int),
		allocatedStorage:      make(map[string]int),
		storagePricing:        0.01,
		redundancyFactor:      3,
		storageUsageHistory:   make(map[string][]int),
	}
}

func (sa *StorageAllocator) AllocateStorage(nodeID string, amount int) error {
	sa.allocationLock.Lock()
	defer sa.allocationLock.Unlock()

	if current, ok := sa.nodeStorageCapacities[nodeID]; ok && current >= amount {
		sa.nodeStorageCapacities[nodeID] -= amount
		sa.allocatedStorage[nodeID] += amount
		return nil
	}
	return errors.New("insufficient storage capacity")
}

func (sa *StorageAllocator) DeallocateStorage(nodeID string, amount int) error {
	sa.allocationLock.Lock()
	defer sa.allocationLock.Unlock()

	if current, ok := sa.allocatedStorage[nodeID]; ok && current >= amount {
		sa.allocatedStorage[nodeID] -= amount
		sa.nodeStorageCapacities[nodeID] += amount
		return nil
	}
	return errors.New("insufficient allocated storage")
}

func (sa *StorageAllocator) AdjustStoragePricing() {
	sa.allocationLock.Lock()
	defer sa.allocationLock.Unlock()

	totalCapacity := 0
	totalAllocated := 0
	for _, capacity := range sa.nodeStorageCapacities {
		totalCapacity += capacity
	}
	for _, allocated := range sa.allocatedStorage {
		totalAllocated += allocated
	}
	usageRatio := float64(totalAllocated) / float64(totalCapacity)

	if usageRatio > 0.8 {
		sa.storagePricing *= 1.1
	} else if usageRatio < 0.5 {
		sa.storagePricing *= 0.9
	}
}

func (sa *StorageAllocator) MonitorAndPredictStorage() {
	for {
		time.Sleep(10 * time.Minute)
		sa.AdjustStoragePricing()

		for nodeID, usageHistory := range sa.storageUsageHistory {
			if len(usageHistory) >= 10 {
				sum := 0
				for _, usage := range usageHistory {
					sum += usage
				}
				averageUsage := sum / len(usageHistory)
				predictedUsage := averageUsage * 1.1
				if err := sa.AllocateStorage(nodeID, predictedUsage); err != nil {
					log.Println("Allocation error:", err)
				}
			}
		}
	}
}

func (sa *StorageAllocator) AddNode(nodeID string, capacity int) {
	sa.allocationLock.Lock()
	defer sa.allocationLock.Unlock()

	sa.nodeStorageCapacities[nodeID] = capacity
	sa.allocatedStorage[nodeID] = 0
}

func (sa *StorageAllocator) RemoveNode(nodeID string) {
	sa.allocationLock.Lock()
	defer sa.allocationLock.Unlock()

	delete(sa.nodeStorageCapacities, nodeID)
	delete(sa.allocatedStorage, nodeID)
}

func (sa *StorageAllocator) MonitorAllocations() {
	ticker := time.NewTicker(5 * time.Minute)
	for {
		select {
		case <-ticker.C:
			sa.allocationLock.Lock()
			for nodeID, allocated := range sa.allocatedStorage {
				if allocated < sa.redundancyFactor {
					if err := sa.AllocateStorage(nodeID, sa.redundancyFactor-allocated); err != nil {
						log.Println("Allocation error:", err)
					}
				}
			}
			sa.allocationLock.Unlock()
		}
	}
}

func encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key []byte) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func NewRedundancyManager(redundancyLevel int) *RedundancyManager {
	return &RedundancyManager{
		redundancyLevel: redundancyLevel,
		storageNodes:    []StorageNode{},
	}
}

func (rm *RedundancyManager) AddNode(node StorageNode) {
	rm.nodeLock.Lock()
	defer rm.nodeLock.Unlock()
	rm.storageNodes = append(rm.storageNodes, node)
}

func (rm *RedundancyManager) RemoveNode(nodeID string) error {
	rm.nodeLock.Lock()
	defer rm.nodeLock.Unlock()

	for i, node := range rm.storageNodes {
		if node.ID == nodeID {
			rm.storageNodes = append(rm.storageNodes[:i], rm.storageNodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

func (rm *RedundancyManager) CheckRedundancy(dataID string) error {
	rm.nodeLock.Lock()
	defer rm.nodeLock.Unlock()

	replicas := rm.getReplicas(dataID)
	if len(replicas) < rm.redundancyLevel {
		err := rm.replicateData(dataID, rm.redundancyLevel-len(replicas))
		if err != nil {
			return err
		}
	}
	return nil
}

func (rm *RedundancyManager) getReplicas(dataID string) []StorageNode {
	replicas := []StorageNode{}
	for _, node := range rm.storageNodes {
		if node.HasData(dataID) {
			replicas = append(replicas, node)
		}
	}
	return replicas
}

func (rm *RedundancyManager) replicateData(dataID string, neededReplicas int) error {
	data, err := rm.fetchData(dataID)
	if err != nil {
		return err
	}

	targetNodes := rm.selectTargetNodes(neededReplicas)
	for _, node := range targetNodes {
		err := node.StoreData(dataID, data)
		if err != nil {
			log.Printf("Failed to store data on node %s: %v", node.ID, err)
		}
	}

	return nil
}

func (rm *RedundancyManager) fetchData(dataID string) ([]byte, error) {
	replicas := rm.getReplicas(dataID)
	if len(replicas) == 0 {
		return nil, errors.New("no replicas found")
	}

	return replicas[0].RetrieveData(dataID)
}

func (rm *RedundancyManager) selectTargetNodes(count int) []StorageNode {
	selected := []StorageNode{}
	for _, node := range rm.storageNodes {
		if len(selected) >= count {
			break
		}
		if !node.IsFull() {
			selected = append(selected, node)
		}
	}
	return selected
}

func (rm *RedundancyManager) MonitorRedundancy(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			rm.adjustRedundancy()
		}
	}
}

func (rm *RedundancyManager) adjustRedundancy() {
	dataList := rm.getAllDataIDs()
	for _, dataID := range dataList {
		err := rm.CheckRedundancy(dataID)
		if err != nil {
			log.Printf("Error adjusting redundancy for data %s: %v", dataID, err)
		}
	}
}

func (rm *RedundancyManager) getAllDataIDs() []string {
	dataIDs := []string{}
	for _, node := range rm.storageNodes {
		dataIDs = append(dataIDs, node.GetDataIDs()...)
	}
	return unique(dataIDs)
}

func unique(data []string) []string {
	uniqueData := make(map[string]struct{})
	for _, item := range data {
		uniqueData[item] = struct{}{}
	}
	var result []string
	for item := range uniqueData {
		result = append(result, item)
	}
	return result
}

func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		storageNodes:       make(map[string]*StorageNode),
		allocationStrategy: &SimpleAllocationStrategy{},
	}
}

func (rm *ResourceManager) RegisterNode(id string, totalSpace int64) {
	rm.nodeLock.Lock()
	defer rm.nodeLock.Unlock()

	rm.storageNodes[id] = &StorageNode{
		ID:         id,
		TotalSpace: totalSpace,
		UsedSpace:  0,
		LastUpdated: time.Now(),
	}
}

func (rm *ResourceManager) UpdateNodeUsage(id string, usedSpace int64) error {
	rm.nodeLock.Lock()
	defer rm.nodeLock.Unlock()

	node, exists := rm.storageNodes[id]
	if !exists {
		return errors.New("node not found")
	}

	node.UsedSpace = usedSpace
	node.LastUpdated = time.Now()
	return nil
}

func (rm *ResourceManager) AllocateStorage(fileSize int64) (string, error) {
	rm.nodeLock.RLock()
	defer rm.nodeLock.RUnlock()

	nodeID, err := rm.allocationStrategy.Allocate(rm.storageNodes, fileSize)
	if err != nil {
		return "", err
	}

	rm.storageNodes[nodeID].UsedSpace += fileSize
	rm.storageNodes[nodeID].LastUpdated = time.Now()

	return nodeID, nil
}

func (rm *ResourceManager) NodeHealthCheck() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.nodeLock.Lock()
			for id, node := range rm.storageNodes {
				if time.Since(node.LastUpdated) > 24*time.Hour {
					delete(rm.storageNodes, id)
					log.Printf("Node %s removed due to inactivity", id)
				}
			}
			rm.nodeLock.Unlock()
		}
	}
}

func (rm *ResourceManager) DecentralizedDecisionMaking() {
	for {
		select {}
	}
}

func (s *SimpleAllocationStrategy) Allocate(storageNodes map[string]*StorageNode, fileSize int64) (string, error) {
	for id, node := range storageNodes {
		if node.TotalSpace-node.UsedSpace >= fileSize {
			return id, nil
		}
	}
	return "", errors.New("no suitable node found")
}

func NewDynamicPricingManager(updateInterval time.Duration) *DynamicPricingManager {
	dpm := &DynamicPricingManager{
		storagePrices:     make(map[string]float64),
		usageStats:        make(map[string]float64),
		priceUpdateTicker: time.NewTicker(updateInterval),
	}

	go dpm.periodicPriceUpdate()

	return dpm
}

func (dpm *DynamicPricingManager) SetUsageStats(fileID string, usage float64) {
	dpm.usageLock.Lock()
	dpm.usageStats[fileID] = usage
	dpm.usageLock.Unlock()
}

func (dpm *DynamicPricingManager) GetStoragePrice(fileID string) float64 {
	dpm.priceLock.Lock()
	defer dpm.priceLock.Unlock()

	if price, exists := dpm.storagePrices[fileID]; exists {
		return price
	}
	return 0.0
}

func (dpm *DynamicPricingManager) periodicPriceUpdate() {
	for range dpm.priceUpdateTicker.C {
		dpm.updatePrices()
	}
}

func (dpm *DynamicPricingManager) updatePrices() {
	dpm.usageLock.Lock()
	usageStatsCopy := make(map[string]float64, len(dpm.usageStats))
	for k, v := range dpm.usageStats {
		usageStatsCopy[k] = v
	}
	dpm.usageLock.Unlock()

	newPrices := dpm.calculateNewPrices(usageStatsCopy)

	dpm.priceLock.Lock()
	for k, v := range newPrices {
		dpm.storagePrices[k] = v
	}
	dpm.priceLock.Unlock()
}

func (dpm *DynamicPricingManager) calculateNewPrices(usageStats map[string]float64) map[string]float64 {
	newPrices := make(map[string]float64, len(usageStats))

	for fileID, usage := range usageStats {
		newPrices[fileID] = dpm.calculatePrice(usage)
	}

	return newPrices
}

func (dpm *DynamicPricingManager) calculatePrice(usage float64) float64 {
	basePrice := 0.01
	demandFactor := 1.0 + usage/100.0

	return basePrice * demandFactor
}

func NewMultiTierStorage(hotPath, coldPath string) (*MultiTierStorage, error) {
	hotStorage, err := NewStorageTier(hotPath)
	if err != nil {
		return nil, err
	}

	coldStorage, err := NewStorageTier(coldPath)
	if err != nil {
		return nil, err
	}

	return &MultiTierStorage{
		hotStorage:  hotStorage,
		coldStorage: coldStorage,
	}, nil
}

func NewStorageTier(basePath string) (*StorageTier, error) {
	if err := os.MkdirAll(basePath, os.ModePerm); err != nil {
		return nil, err
	}
	return &StorageTier{
		basePath: basePath,
		files:    make(map[string]*StoredFile),
	}, nil
}

func (mts *MultiTierStorage) StoreFile(fileID string, data []byte, hot bool) error {
	mts.tierLock.Lock()
	defer mts.tierLock.Unlock()

	if hot {
		return mts.hotStorage.StoreFile(fileID, data)
	}
	return mts.coldStorage.StoreFile(fileID, data)
}

func (mts *MultiTierStorage) RetrieveFile(fileID string) ([]byte, error) {
	mts.tierLock.Lock()
	defer mts.tierLock.Unlock()

	data, err := mts.hotStorage.RetrieveFile(fileID)
	if err == nil {
		return data, nil
	}

	return mts.coldStorage.RetrieveFile(fileID)
}

func (mts *MultiTierStorage) TransferToCold(fileID string) error {
	mts.tierLock.Lock()
	defer mts.tierLock.Unlock()

	data, err := mts.hotStorage.RetrieveFile(fileID)
	if err != nil {
		return err
	}

	if err := mts.coldStorage.StoreFile(fileID, data); err != nil {
		return err
	}

	return mts.hotStorage.DeleteFile(fileID)
}

func (mts *MultiTierStorage) TransferToHot(fileID string) error {
	mts.tierLock.Lock()
	defer mts.tierLock.Unlock()

	data, err := mts.coldStorage.RetrieveFile(fileID)
	if err != nil {
		return err
	}

	if err := mts.hotStorage.StoreFile(fileID, data); err != nil {
		return err
	}

	return mts.coldStorage.DeleteFile(fileID)
}

func (st *StorageTier) StoreFile(fileID string, data []byte) error {
	st.fileLock.Lock()
	defer st.fileLock.Unlock()

	filePath := filepath.Join(st.basePath, fileID)
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return err
	}

	st.files[fileID] = &StoredFile{
		Data:        data,
		LastAccess:  time.Now(),
		AccessCount: 1,
	}

	return nil
}

func (st *StorageTier) RetrieveFile(fileID string) ([]byte, error) {
	st.fileLock.RLock()
	defer st.fileLock.RUnlock()

	file, exists := st.files[fileID]
	if !exists {
		return nil, errors.New("file not found")
	}

	file.LastAccess = time.Now()
	file.AccessCount++

	return file.Data, nil
}

func (st *StorageTier) DeleteFile(fileID string) error {
	st.fileLock.Lock()
	defer st.fileLock.Unlock()

	filePath := filepath.Join(st.basePath, fileID)
	if err := os.Remove(filePath); err != nil {
		return err
	}

	delete(st.files, fileID)
	return nil
}

func (mts *MultiTierStorage) MonitorAndAdjust(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			mts.adjustStorageTiers()
		}
	}
}

func (mts *MultiTierStorage) adjustStorageTiers() {
	mts.tierLock.Lock()
	defer mts.tierLock.Unlock()

	for fileID, file := range mts.hotStorage.files {
		if file.AccessCount < 5 {
			mts.TransferToCold(fileID)
		}
	}

	for fileID, file := range mts.coldStorage.files {
		if file.AccessCount >= 5 {
			mts.TransferToHot(fileID)
		}
	}
}

func NewSecureStorageManager(key []byte) (*SecureStorageManager, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes long")
	}
	return &SecureStorageManager{
		encryptionKey: key,
		storage:       make(map[string]string),
	}, nil
}

func (ssm *SecureStorageManager) EncryptAndStore(fileID string, data []byte) error {
	encryptedData, err := ssm.encrypt(data)
	if err != nil {
		return err
	}

	ssm.storageLock.Lock()
	defer ssm.storageLock.Unlock()

	ssm.storage[fileID] = encryptedData
	return nil
}

func (ssm *SecureStorageManager) RetrieveAndDecrypt(fileID string) ([]byte, error) {
	ssm.storageLock.Lock()
	encryptedData, exists := ssm.storage[fileID]
	ssm.storageLock.Unlock()

	if !exists {
		return nil, errors.New("file not found")
	}

	return ssm.decrypt(encryptedData)
}

func (ssm *SecureStorageManager) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(ssm.encryptionKey)
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
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (ssm *SecureStorageManager) decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ssm.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (ssm *SecureStorageManager) EndToEndEncryptAndStore(fileID string, data []byte, recipientPublicKey []byte) error {
	encryptedData, err := ssm.encrypt(data)
	if err != nil {
		return err
	}

	encryptedForRecipient, err := encryptWithPublicKey([]byte(encryptedData), recipientPublicKey)
	if err != nil {
		return err
	}

	ssm.storageLock.Lock()
	defer ssm.storageLock.Unlock()

	ssm.storage[fileID] = base64.StdEncoding.EncodeToString(encryptedForRecipient)
	return nil
}

func encryptWithPublicKey(data []byte, publicKey []byte) ([]byte, error) {
	// Placeholder for actual public key encryption logic
	return data, nil
}

func decryptWithPrivateKey(encryptedData []byte, privateKey []byte) ([]byte, error) {
	// Placeholder for actual private key decryption logic
	return encryptedData, nil
}

func (ssm *SecureStorageManager) EndToEndRetrieveAndDecrypt(fileID string, recipientPrivateKey []byte) ([]byte, error) {
	ssm.storageLock.Lock()
	encryptedData, exists := ssm.storage[fileID]
	ssm.storageLock.Unlock()

	if !exists {
		return nil, errors.New("file not found")
	}

	encryptedForRecipient, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptWithPrivateKey(encryptedForRecipient, recipientPrivateKey)
	if err != nil {
		return nil, err
	}

	return ssm.decrypt(string(decryptedData))
}

func (ssm *SecureStorageManager) RoleBasedEncryptAndStore(fileID string, data []byte, role string, roleKeys map[string][]byte) error {
	encryptedData, err := ssm.encrypt(data)
	if err != nil {
		return err
	}

	encryptedForRole, err := encryptWithPublicKey([]byte(encryptedData), roleKeys[role])
	if err != nil {
		return err
	}

	ssm.storageLock.Lock()
	defer ssm.storageLock.Unlock()

	ssm.storage[fileID] = base64.StdEncoding.EncodeToString(encryptedForRole)
	return nil
}

func (ssm *SecureStorageManager) RoleBasedRetrieveAndDecrypt(fileID string, role string, rolePrivateKey []byte) ([]byte, error) {
	ssm.storageLock.Lock()
	encryptedData, exists := ssm.storage[fileID]
	ssm.storageLock.Unlock()

	if !exists {
		return nil, errors.New("file not found")
	}

	encryptedForRole, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptWithPrivateKey(encryptedForRole, rolePrivateKey)
	if err != nil {
		return nil, err
	}

	return ssm.decrypt(string(decryptedData))
}

func NewStorageManager(contractAddress string) (*StorageManager, error) {
	sc, err := loadContract(contractAddress)
	if err != nil {
		return nil, err
	}

	return &StorageManager{
		allocations:  make(map[string]StorageAllocation),
		pricingModel: &DynamicPricingModel{BasePrice: 0.01, CurrentPrice: 0.01, PricingFactor: 1.1},
		sc:           sc,
	}, nil
}

func (sm *StorageManager) AllocateStorage(nodeID string, size int64) error {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	if _, exists := sm.allocations[nodeID]; exists {
		return errors.New("storage already allocated for this node")
	}

	price := sm.calculatePrice(size)
	transaction := newTransaction(nodeID, sm.sc.Address, price)

	if err := sm.sc.ExecuteTransaction(transaction); err != nil {
		return err
	}

	sm.allocations[nodeID] = StorageAllocation{
		NodeID:    nodeID,
		Size:      size,
		Timestamp: time.Now(),
	}

	return nil
}

func (sm *StorageManager) ReleaseStorage(nodeID string) error {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	if _, exists := sm.allocations[nodeID]; !exists {
		return errors.New("no storage allocated for this node")
	}

	delete(sm.allocations, nodeID)
	return nil
}

func (sm *StorageManager) GetAllocation(nodeID string) (StorageAllocation, error) {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	allocation, exists := sm.allocations[nodeID]
	if !exists {
		return StorageAllocation{}, errors.New("no storage allocated for this node")
	}

	return allocation, nil
}

func (sm *StorageManager) MonitorAllocations() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		sm.performMonitoring()
	}
}

func (sm *StorageManager) performMonitoring() {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	for nodeID, allocation := range sm.allocations {
		if time.Since(allocation.Timestamp).Hours() > 24 {
			log.Printf("Releasing stale allocation for node %s\n", nodeID)
			delete(sm.allocations, nodeID)
		}
	}
}

func (sm *StorageManager) calculatePrice(size int64) float64 {
	sm.pricingModel.CurrentPrice = sm.pricingModel.BasePrice * sm.pricingModel.PricingFactor
	return sm.pricingModel.CurrentPrice * float64(size)
}

func (sm *StorageManager) DynamicPricingUpdate(factor float64) {
	sm.pricingModel.PricingFactor = factor
}

func (sm *StorageManager) SaveAllocationsToFile(filePath string) error {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	data, err := json.Marshal(sm.allocations)
	if err != nil {
		return err
	}

	return saveToFile(filePath, data)
}

func saveToFile(filePath string, data []byte) error {
	return ioutil.WriteFile(filePath, data, 0644)
}

func loadFromFile(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}

func (sm *StorageManager) LoadAllocationsFromFile(filePath string) error {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	data, err := loadFromFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &sm.allocations)
}

func (sm *StorageManager) GenerateStorageReport() string {
	sm.allocationsMutex.Lock()
	defer sm.allocationsMutex.Unlock()

	report := "Storage Allocations Report:\n"
	for nodeID, allocation := range sm.allocations {
		report += fmt.Sprintf("NodeID: %s, Size: %d, Timestamp: %s\n", nodeID, allocation.Size, allocation.Timestamp.String())
	}
	return report
}

func loadContract(contractAddress string) (*smartContract, error) {
	// Placeholder for loading the actual contract
	return &smartContract{Address: contractAddress}, nil
}

type smartContract struct {
	Address string
}

func (sc *smartContract) ExecuteTransaction(tx *transaction) error {
	// Placeholder for executing the transaction on the smart contract
	return nil
}

func newTransaction(nodeID, contractAddress string, price float64) *transaction {
	// Placeholder for creating a new transaction
	return &transaction{NodeID: nodeID, ContractAddress: contractAddress, Price: price}
}

type transaction struct {
	NodeID          string
	ContractAddress string
	Price           float64
}

func main() {
	storageAllocator := NewStorageAllocator()
	storageAllocator.AddNode("node1", 1000)
	storageAllocator.AddNode("node2", 1500)

	if err := storageAllocator.AllocateStorage("node1", 100); err != nil {
		log.Println(err)
	}

	go storageAllocator.MonitorAndPredictStorage()
	go storageAllocator.MonitorAllocations()

	sm, err := NewStorageManager("contract_address")
	if err != nil {
		log.Fatalf("Failed to create Storage Manager: %v", err)
	}

	go sm.MonitorAllocations()

	http.HandleFunc("/allocate", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node_id")
		sizeStr := r.URL.Query().Get("size")
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid size parameter", http.StatusBadRequest)
			return
		}

		err = sm.AllocateStorage(nodeID, size)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Storage allocated successfully"))
	})

	http.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node_id")

		err := sm.ReleaseStorage(nodeID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Storage released successfully"))
	})

	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		report := sm.GenerateStorageReport()
		w.Write([]byte(report))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Secure Storage Manager functions
func NewSecureStorageManager() *SecureStorageManager {
	return &SecureStorageManager{
		keyStore: make(map[string][]byte),
	}
}

func (ssm *SecureStorageManager) EncryptData(data []byte, keyID string) (string, error) {
	key, err := ssm.getKey(keyID)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
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
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (ssm *SecureStorageManager) DecryptData(encodedData string, keyID string) ([]byte, error) {
	key, err := ssm.getKey(keyID)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (ssm *SecureStorageManager) getKey(keyID string) ([]byte, error) {
	ssm.keyStoreLock.Lock()
	defer ssm.keyStoreLock.Unlock()

	key, exists := ssm.keyStore[keyID]
	if !exists {
		return nil, errors.New("key not found")
	}

	return key, nil
}

func (ssm *SecureStorageManager) AddKey(keyID string, key []byte) {
	ssm.keyStoreLock.Lock()
	defer ssm.keyStoreLock.Unlock()

	ssm.keyStore[keyID] = key
}

func (ssm *SecureStorageManager) RotateKey(keyID string) ([]byte, error) {
	ssm.keyStoreLock.Lock()
	defer ssm.keyStoreLock.Unlock()

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return nil, err
	}

	ssm.keyStore[keyID] = newKey
	return newKey, nil
}

func (ssm *SecureStorageManager) PeriodicKeyRotation(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			ssm.rotateAllKeys()
		}
	}
}

func (ssm *SecureStorageManager) rotateAllKeys() {
	ssm.keyStoreLock.Lock()
	defer ssm.keyStoreLock.Unlock()

	for keyID := range ssm.keyStore {
		newKey := make([]byte, 32)
		if _, err := rand.Read(newKey); err != nil {
			continue // Handle error appropriately in a real-world scenario
		}
		ssm.keyStore[keyID] = newKey
	}
}

func (ssm *SecureStorageManager) SecurelyStoreData(data []byte, keyID string, roleID string) (string, error) {
	// Role-based access control check
	if !hasAccess(roleID, keyID) {
		return "", errors.New("access denied")
	}

	encryptedData, err := ssm.EncryptData(data, keyID)
	if err != nil {
		return "", err
	}

	// Store the encrypted data (mock implementation, replace with actual storage logic)
	storeData(keyID, encryptedData)

	return encryptedData, nil
}

func (ssm *SecureStorageManager) SecurelyRetrieveData(keyID string, roleID string) ([]byte, error) {
	// Role-based access control check
	if !hasAccess(roleID, keyID) {
		return nil, errors.New("access denied")
	}

	// Retrieve the encrypted data (mock implementation, replace with actual retrieval logic)
	encryptedData, err := retrieveData(keyID)
	if err != nil {
		return nil, err
	}

	return ssm.DecryptData(encryptedData, keyID)
}

// Mock functions for role-based access and data storage/retrieval (replace with actual implementations)
func hasAccess(roleID, keyID string) bool {
	// Placeholder for role-based access control check
	return true
}

func storeData(keyID, data string) {
	// Placeholder for storing data
}

func retrieveData(keyID string) (string, error) {
	// Placeholder for retrieving data
	return "", nil
}

