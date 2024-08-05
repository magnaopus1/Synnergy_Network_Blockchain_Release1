package utils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
)

type Config struct {
	NetworkID             string `json:"network_id"`
	StoragePath           string `json:"storage_path"`
	MaxConnections        int    `json:"max_connections"`
	EnableTLS             bool   `json:"enable_tls"`
	TLSCertPath           string `json:"tls_cert_path"`
	TLSKeyPath            string `json:"tls_key_path"`
}

var (
	config     *Config
	configLock sync.Mutex
)

// LoadConfig reads the configuration from the specified file path
func LoadConfig(filePath string) (*Config, error) {
	configLock.Lock()
	defer configLock.Unlock()

	if config != nil {
		return config, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

// validateConfig ensures that the loaded configuration has all necessary fields
func validateConfig(cfg *Config) error {
	if cfg.NetworkID == "" {
		return errors.New("network ID is required")
	}
	if cfg.StoragePath == "" {
		return errors.New("storage path is required")
	}
	if cfg.MaxConnections <= 0 {
		return errors.New("max connections must be greater than zero")
	}
	if cfg.EnableTLS {
		if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
			return errors.New("TLS cert and key paths are required when TLS is enabled")
		}
	}
	return nil
}
package utils

import (
	"log"
	"os"
	"runtime"
)

// Custom error types
type StorageError struct {
	Message string
	Err     error
}

func (e *StorageError) Error() string {
	return e.Message
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

type ConfigError struct {
	Message string
	Err     error
}

func (e *ConfigError) Error() string {
	return e.Message
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// LogError logs an error to the standard logger
func LogError(err error) {
	_, file, line, _ := runtime.Caller(1)
	log.Printf("ERROR: %s:%d: %v\n", file, line, err)
}

// HandleError logs an error and exits the program if it's critical
func HandleError(err error, critical bool) {
	LogError(err)
	if critical {
		os.Exit(1)
	}
}

// RecoverPanic logs a panic and recovers from it
func RecoverPanic() {
	if r := recover(); r != nil {
		LogError(&StorageError{Message: "panic recovered", Err: r.(error)})
	}
}
package utils

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/cryptography/encryption"
)

// LogLevel represents the severity level of the log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// Logger struct encapsulates the logging logic
type Logger struct {
	mu           sync.Mutex
	level        LogLevel
	logFile      *os.File
	remoteServer string
	remote       bool
}

// NewLogger initializes a new logger instance
func NewLogger(logLevel LogLevel, logFilePath string, remoteServer string) (*Logger, error) {
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, err
	}

	return &Logger{
		level:        logLevel,
		logFile:      logFile,
		remoteServer: remoteServer,
		remote:       remoteServer != "",
	}, nil
}

// LogMessage represents a structured log message
type LogMessage struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

// Close closes the log file
func (l *Logger) Close() error {
	return l.logFile.Close()
}

// log writes a log message with the given level and message
func (l *Logger) log(level LogLevel, message string) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	logMessage := LogMessage{
		Timestamp: time.Now(),
		Level:     l.levelToString(level),
		Message:   message,
	}

	logOutput := fmt.Sprintf("%s [%s]: %s\n", logMessage.Timestamp.Format(time.RFC3339), logMessage.Level, logMessage.Message)

	// Write to local log file
	if _, err := l.logFile.WriteString(logOutput); err != nil {
		log.Fatalf("Failed to write log to file: %v", err)
	}

	// Optionally send log to remote server
	if l.remote {
		if err := l.sendToRemote(logOutput); err != nil {
			log.Printf("Failed to send log to remote server: %v", err)
		}
	}

	// Print to console
	log.Print(logOutput)
}

// sendToRemote sends the log message to a remote server
func (l *Logger) sendToRemote(message string) error {
	encryptedMessage, err := encryption.EncryptMessage(message)
	if err != nil {
		return err
	}

	// Placeholder for actual remote logging implementation
	// Example: Send encryptedMessage to l.remoteServer using HTTP or gRPC
	fmt.Printf("Sending to remote server %s: %s\n", l.remoteServer, encryptedMessage)
	return nil
}

// LogDebug logs a debug message
func (l *Logger) LogDebug(message string) {
	l.log(DEBUG, message)
}

// LogInfo logs an informational message
func (l *Logger) LogInfo(message string) {
	l.log(INFO, message)
}

// LogWarn logs a warning message
func (l *Logger) LogWarn(message string) {
	l.log(WARN, message)
}

// LogError logs an error message
func (l *Logger) LogError(message string) {
	l.log(ERROR, message)
}

// LogFatal logs a fatal error message and exits the application
func (l *Logger) LogFatal(message string) {
	l.log(FATAL, message)
	os.Exit(1)
}

// levelToString converts the log level to a string representation
func (l *Logger) levelToString(level LogLevel) string {
	switch level {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}
package utils

import (
	"fmt"
	"sync"
	"time"
	"encoding/json"
	"log"
	"os"
	"runtime"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/network"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/consensus"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/file_storage/utils"
)

type PerformanceMetrics struct {
	metrics        map[string]interface{}
	metricsLock    sync.Mutex
	updateInterval time.Duration
	stopChan       chan bool
}

func NewPerformanceMetrics(updateInterval time.Duration) *PerformanceMetrics {
	pm := &PerformanceMetrics{
		metrics:        make(map[string]interface{}),
		updateInterval: updateInterval,
		stopChan:       make(chan bool),
	}
	go pm.start()
	return pm
}

func (pm *PerformanceMetrics) start() {
	ticker := time.NewTicker(pm.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pm.updateMetrics()
		case <-pm.stopChan:
			return
		}
	}
}

func (pm *PerformanceMetrics) Stop() {
	pm.stopChan <- true
}

func (pm *PerformanceMetrics) updateMetrics() {
	pm.metricsLock.Lock()
	defer pm.metricsLock.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	pm.metrics["Alloc"] = m.Alloc
	pm.metrics["TotalAlloc"] = m.TotalAlloc
	pm.metrics["Sys"] = m.Sys
	pm.metrics["Mallocs"] = m.Mallocs
	pm.metrics["Frees"] = m.Frees
	pm.metrics["HeapAlloc"] = m.HeapAlloc
	pm.metrics["HeapSys"] = m.HeapSys
	pm.metrics["NumGC"] = m.NumGC
	pm.metrics["NumGoroutine"] = runtime.NumGoroutine()
	pm.metrics["CpuUsage"] = getCPUUsage()
}

func getCPUUsage() float64 {
	// Placeholder function for CPU usage calculation
	// Implement actual CPU usage calculation if needed
	return 0.0
}

func (pm *PerformanceMetrics) GetMetrics() map[string]interface{} {
	pm.metricsLock.Lock()
	defer pm.metricsLock.Unlock()
	
	copy := make(map[string]interface{}, len(pm.metrics))
	for k, v := range pm.metrics {
		copy[k] = v
	}
	return copy
}

func (pm *PerformanceMetrics) SaveMetricsToFile(filename string) error {
	pm.metricsLock.Lock()
	defer pm.metricsLock.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(pm.metrics)
}

func (pm *PerformanceMetrics) LoadMetricsFromFile(filename string) error {
	pm.metricsLock.Lock()
	defer pm.metricsLock.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(&pm.metrics)
}

// Additional Functions for Enhanced Metrics

func (pm *PerformanceMetrics) LogMetrics() {
	pm.metricsLock.Lock()
	defer pm.metricsLock.Unlock()

	for k, v := range pm.metrics {
		log.Printf("%s: %v", k, v)
	}
}

func (pm *PerformanceMetrics) MonitorDiskUsage() {
	// Placeholder for disk usage monitoring implementation
	// Implement actual disk usage monitoring
	pm.metrics["DiskUsage"] = "N/A"
}

func (pm *PerformanceMetrics) MonitorNetworkUsage() {
	// Placeholder for network usage monitoring implementation
	// Implement actual network usage monitoring
	pm.metrics["NetworkUsage"] = "N/A"
}

func main() {
	updateInterval := 10 * time.Second
	pm := NewPerformanceMetrics(updateInterval)

	// Example usage of the performance metrics module
	time.Sleep(1 * time.Minute)
	pm.LogMetrics()
	err := pm.SaveMetricsToFile("metrics.json")
	if err != nil {
		fmt.Println("Error saving metrics:", err)
	}

	pm.Stop()
}
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/file_storage/data_replication"
	"github.com/synnergy_network/storage"
)

// CachingLayer represents a caching layer with in-memory and distributed caching mechanisms.
type CachingLayer struct {
	memoryCache *cache.Cache
	redisCache  *RedisCache // Assuming RedisCache is a struct that handles Redis operations
	lock        sync.RWMutex
}

// NewCachingLayer initializes a new caching layer with in-memory and distributed caching.
func NewCachingLayer(defaultExpiration, cleanupInterval time.Duration, redisAddress string) *CachingLayer {
	redisCache := NewRedisCache(redisAddress) // Initialize Redis cache
	return &CachingLayer{
		memoryCache: cache.New(defaultExpiration, cleanupInterval),
		redisCache:  redisCache,
	}
}

// CacheItem represents an item to be cached with its hash and timestamp.
type CacheItem struct {
	Hash      string    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data"`
}

// HashData generates a SHA-256 hash for the given data.
func HashData(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// Set sets a new item in the cache.
func (cl *CachingLayer) Set(key string, value []byte) {
	cl.lock.Lock()
	defer cl.lock.Unlock()

	hash := HashData(value)
	timestamp := time.Now()
	item := CacheItem{
		Hash:      hash,
		Timestamp: timestamp,
		Data:      value,
	}

	cl.memoryCache.Set(key, item, cache.DefaultExpiration)
	cl.redisCache.Set(key, item)
}

// Get retrieves an item from the cache.
func (cl *CachingLayer) Get(key string) ([]byte, bool) {
	cl.lock.RLock()
	defer cl.lock.RUnlock()

	if x, found := cl.memoryCache.Get(key); found {
		item := x.(CacheItem)
		return item.Data, true
	}

	if x, found := cl.redisCache.Get(key); found {
		cl.memoryCache.Set(key, x, cache.DefaultExpiration)
		item := x.(CacheItem)
		return item.Data, true
	}

	return nil, false
}

// Invalidate invalidates a specific cache item.
func (cl *CachingLayer) Invalidate(key string) {
	cl.lock.Lock()
	defer cl.lock.Unlock()
	cl.memoryCache.Delete(key)
	cl.redisCache.Delete(key)
}

// Clear clears the entire cache.
func (cl *CachingLayer) Clear() {
	cl.lock.Lock()
	defer cl.lock.Unlock()
	cl.memoryCache.Flush()
	cl.redisCache.Flush()
}

// RedisCache represents the distributed Redis caching layer.
type RedisCache struct {
	// Assuming RedisClient is a struct that handles Redis operations
	client *RedisClient
}

// NewRedisCache initializes a new Redis cache.
func NewRedisCache(address string) *RedisCache {
	client := NewRedisClient(address) // Initialize Redis client
	return &RedisCache{client: client}
}

// Set sets a new item in the Redis cache.
func (rc *RedisCache) Set(key string, item CacheItem) {
	data, err := json.Marshal(item)
	if err != nil {
		panic(err)
	}
	rc.client.Set(key, data, 0)
}

// Get retrieves an item from the Redis cache.
func (rc *RedisCache) Get(key string) (CacheItem, bool) {
	data, err := rc.client.Get(key)
	if err != nil {
		return CacheItem{}, false
	}
	var item CacheItem
	err = json.Unmarshal(data, &item)
	if err != nil {
		return CacheItem{}, false
	}
	return item, true
}

// Delete deletes an item from the Redis cache.
func (rc *RedisCache) Delete(key string) {
	rc.client.Delete(key)
}

// Flush clears the entire Redis cache.
func (rc *RedisCache) Flush() {
	rc.client.FlushAll()
}

// RedisClient represents a mock Redis client. Replace with actual Redis client implementation.
type RedisClient struct {
	address string
	cache   map[string][]byte
}

// NewRedisClient initializes a new Redis client.
func NewRedisClient(address string) *RedisClient {
	return &RedisClient{
		address: address,
		cache:   make(map[string][]byte),
	}
}

// Set sets a key-value pair in Redis.
func (rc *RedisClient) Set(key string, value []byte, expiration time.Duration) {
	rc.cache[key] = value
}

// Get retrieves a value from Redis.
func (rc *RedisClient) Get(key string) ([]byte, error) {
	value, exists := rc.cache[key]
	if !exists {
		return nil, utils.ErrCacheMiss
	}
	return value, nil
}

// Delete deletes a key from Redis.
func (rc *RedisClient) Delete(key string) {
	delete(rc.cache, key)
}

// FlushAll clears the entire Redis cache.
func (rc *RedisClient) FlushAll() {
	rc.cache = make(map[string][]byte)
}
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/file_storage/data_replication"
	"github.com/synnergy_network/storage"
	"github.com/synnergy_network/network/rate_limiting"
	"github.com/synnergy_network/security"
	"github.com/synnergy_network/consensus"
	"github.com/synnergy_network/scalability"
	"github.com/synnergy_network/compliance"
)

// CachingLayer represents a caching layer with in-memory and distributed caching mechanisms.
type CachingLayer struct {
	inMemoryCache  *cache.Cache
	distributedCache DistributedCache
	mu              sync.Mutex
}

// DistributedCache interface for implementing distributed caching.
type DistributedCache interface {
	Get(key string) (interface{}, error)
	Set(key string, value interface{}, duration time.Duration) error
	Delete(key string) error
}

// NewCachingLayer initializes a new caching layer.
func NewCachingLayer(defaultExpiration, cleanupInterval time.Duration, distributedCache DistributedCache) *CachingLayer {
	inMemoryCache := cache.New(defaultExpiration, cleanupInterval)
	return &CachingLayer{
		inMemoryCache:  inMemoryCache,
		distributedCache: distributedCache,
	}
}

// Set stores a value in both in-memory and distributed cache.
func (cl *CachingLayer) Set(key string, value interface{}, duration time.Duration) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Store in in-memory cache
	cl.inMemoryCache.Set(key, value, duration)

	// Store in distributed cache
	err := cl.distributedCache.Set(key, value, duration)
	if err != nil {
		return err
	}

	return nil
}

// Get retrieves a value from the cache.
func (cl *CachingLayer) Get(key string) (interface{}, error) {
	// Try to get from in-memory cache
	if value, found := cl.inMemoryCache.Get(key); found {
		return value, nil
	}

	// Fallback to distributed cache
	value, err := cl.distributedCache.Get(key)
	if err != nil {
		return nil, err
	}

	// Store in in-memory cache for faster access next time
	cl.inMemoryCache.Set(key, value, cache.DefaultExpiration)

	return value, nil
}

// Delete removes a value from both in-memory and distributed cache.
func (cl *CachingLayer) Delete(key string) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Delete from in-memory cache
	cl.inMemoryCache.Delete(key)

	// Delete from distributed cache
	err := cl.distributedCache.Delete(key)
	if err != nil {
		return err
	}

	return nil
}

// CacheKey generates a unique cache key using SHA-256.
func CacheKey(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write(jsonData)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// DistributedCache implementation using Redis
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache initializes a new Redis cache.
func NewRedisCache(addr string, password string, db int) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &RedisCache{client: client}
}

// Get retrieves a value from Redis.
func (rc *RedisCache) Get(key string) (interface{}, error) {
	value, err := rc.client.Get(key).Result()
	if err == redis.Nil {
		return nil, errors.New("key does not exist")
	} else if err != nil {
		return nil, err
	}

	var result interface{}
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Set stores a value in Redis.
func (rc *RedisCache) Set(key string, value interface{}, duration time.Duration) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	err = rc.client.Set(key, jsonValue, duration).Err()
	if err != nil {
		return err
	}

	return nil
}

// Delete removes a value from Redis.
func (rc *RedisCache) Delete(key string) error {
	err := rc.client.Del(key).Err()
	if err != nil {
		return err
	}

	return nil
}

// Ensure security by integrating encryption
func (cl *CachingLayer) SetWithEncryption(key string, value interface{}, duration time.Duration, encryptionKey []byte) error {
	encryptedValue, err := security.Encrypt(value, encryptionKey)
	if err != nil {
		return err
	}

	return cl.Set(key, encryptedValue, duration)
}

func (cl *CachingLayer) GetWithDecryption(key string, encryptionKey []byte) (interface{}, error) {
	encryptedValue, err := cl.Get(key)
	if err != nil {
		return nil, err
	}

	decryptedValue, err := security.Decrypt(encryptedValue.([]byte), encryptionKey)
	if err != nil {
		return nil, err
	}

	return decryptedValue, nil
}

// Implement rate limiting
func (cl *CachingLayer) SetWithRateLimit(key string, value interface{}, duration time.Duration, rateLimiter *rate_limiting.RateLimiter) error {
	if rateLimiter.Allow() {
		return cl.Set(key, value, duration)
	}
	return errors.New("rate limit exceeded")
}

func (cl *CachingLayer)
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/synnergy_network/blockchain/crypto"
	"github.com/synnergy_network/blockchain/utils"
	"github.com/synnergy_network/file_storage/data_replication"
	"github.com/synnergy_network/storage"
)

// CacheLayer interface represents a caching layer with in-memory and distributed caching mechanisms.
type CacheLayer interface {
	Set(key string, value interface{}, duration time.Duration) error
	Get(key string) (interface{}, error)
	Delete(key string) error
}

// MemoryCache represents an in-memory caching layer.
type MemoryCache struct {
	cache *cache.Cache
}

// NewMemoryCache creates a new instance of MemoryCache.
func NewMemoryCache(defaultExpiration, cleanupInterval time.Duration) *MemoryCache {
	return &MemoryCache{
		cache: cache.New(defaultExpiration, cleanupInterval),
	}
}

// Set adds an item to the in-memory cache.
func (m *MemoryCache) Set(key string, value interface{}, duration time.Duration) error {
	m.cache.Set(key, value, duration)
	return nil
}

// Get retrieves an item from the in-memory cache.
func (m *MemoryCache) Get(key string) (interface{}, error) {
	value, found := m.cache.Get(key)
	if !found {
		return nil, errors.New("item not found in cache")
	}
	return value, nil
}

// Delete removes an item from the in-memory cache.
func (m *MemoryCache) Delete(key string) error {
	m.cache.Delete(key)
	return nil
}

// DistributedCache represents a distributed caching layer.
type DistributedCache struct {
	// Implement distributed cache client (e.g., Redis, Memcached)
	// For example purposes, using a simple map with mutex for thread safety
	data map[string]interface{}
	mu   sync.RWMutex
}

// NewDistributedCache creates a new instance of DistributedCache.
func NewDistributedCache() *DistributedCache {
	return &DistributedCache{
		data: make(map[string]interface{}),
	}
}

// Set adds an item to the distributed cache.
func (d *DistributedCache) Set(key string, value interface{}, duration time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[key] = value
	// Add expiration logic as per the distributed cache used
	return nil
}

// Get retrieves an item from the distributed cache.
func (d *DistributedCache) Get(key string) (interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	value, exists := d.data[key]
	if !exists {
		return nil, errors.New("item not found in cache")
	}
	return value, nil
}

// Delete removes an item from the distributed cache.
func (d *DistributedCache) Delete(key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.data, key)
	return nil
}

// CachingLayerUtil provides a unified interface for caching operations.
type CachingLayerUtil struct {
	memoryCache      *MemoryCache
	distributedCache *DistributedCache
}

// NewCachingLayerUtil creates a new instance of CachingLayerUtil.
func NewCachingLayerUtil(memoryCache *MemoryCache, distributedCache *DistributedCache) *CachingLayerUtil {
	return &CachingLayerUtil{
		memoryCache:      memoryCache,
		distributedCache: distributedCache,
	}
}

// Set adds an item to the appropriate cache layer.
func (c *CachingLayerUtil) Set(key string, value interface{}, duration time.Duration) error {
	hashedKey := c.hashKey(key)
	err := c.memoryCache.Set(hashedKey, value, duration)
	if err != nil {
		return err
	}
	err = c.distributedCache.Set(hashedKey, value, duration)
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves an item from the appropriate cache layer.
func (c *CachingLayerUtil) Get(key string) (interface{}, error) {
	hashedKey := c.hashKey(key)
	value, err := c.memoryCache.Get(hashedKey)
	if err == nil {
		return value, nil
	}
	value, err = c.distributedCache.Get(hashedKey)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// Delete removes an item from the appropriate cache layer.
func (c *CachingLayerUtil) Delete(key string) error {
	hashedKey := c.hashKey(key)
	err := c.memoryCache.Delete(hashedKey)
	if err != nil {
		return err
	}
	err = c.distributedCache.Delete(hashedKey)
	if err != nil {
		return err
	}
	return nil
}

// hashKey generates a SHA-256 hash of the given key.
func (c *CachingLayerUtil) hashKey(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

// Encryption/Decryption utilities (using AES and Scrypt for this example)
func encryptData(key, plaintext string) (string, error) {
	encrypted, err := crypto.EncryptAES([]byte(key), []byte(plaintext))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encrypted), nil
}

func decryptData(key, ciphertext string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, err := crypto.DecryptAES([]byte(key), data)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// Function to securely store sensitive data
func (c *CachingLayerUtil) SecureSet(key, plaintext string, duration time.Duration) error {
	hashedKey := c.hashKey(key)
	encryptedData, err := encryptData(key, plaintext)
	if err != nil {
		return err
	}
	err = c.memoryCache.Set(hashedKey, encryptedData, duration)
	if err != nil {
		return err
	}
	err = c.distributedCache.Set(hashedKey, encryptedData, duration)
	if err != nil {
		return err
	}
	return nil
}

// Function to retrieve and decrypt sensitive data
func (c *CachingLayerUtil) SecureGet(key string) (string, error) {
	hashedKey := c.hashKey(key)
	encryptedData, err := c.memoryCache.Get(hashedKey)
	if err != nil {
		encryptedData, err = c.distributedCache.Get(hashedKey)
		if err != nil {
			return "", err
		}
	}
	plaintext, err := decryptData(key, encryptedData.(string))
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

package utils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/synnergy_network/blockchain/utils/logger"
)

// Define custom error types
type BlockchainError struct {
	Code    int
	Message string
	Details string
}

func (e *BlockchainError) Error() string {
	return fmt.Sprintf("Error Code: %d, Message: %s, Details: %s", e.Code, e.Message, e.Details)
}

// Error codes
const (
	ErrCodeInvalidTransaction   = 1001
	ErrCodeInvalidBlock         = 1002
	ErrCodeNetworkFailure       = 1003
	ErrCodeInsufficientFunds    = 1004
	ErrCodeUnauthorizedAccess   = 1005
	ErrCodeDataCorruption       = 1006
	ErrCodeConsensusFailure     = 1007
	ErrCodeSmartContractFailure = 1008
)

// Centralized error logging function
func LogError(err error) {
	pc, fn, line, _ := runtime.Caller(1)
	logMessage := fmt.Sprintf("[ERROR] %s:%d %s: %v", fn, line, runtime.FuncForPC(pc).Name(), err)
	logToFile(logMessage)
	fmt.Println(logMessage)
}

// Log errors to a file
func logToFile(message string) {
	f, err := os.OpenFile("blockchain_errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("error opening file: ", err)
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags)
	logger.Println(message)
}

// Centralized error handling function
func HandleError(err error) {
	if err != nil {
		LogError(err)
	}
}

// Helper functions to create new errors
func NewBlockchainError(code int, message, details string) error {
	return &BlockchainError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

func NewInvalidTransactionError(details string) error {
	return NewBlockchainError(ErrCodeInvalidTransaction, "Invalid Transaction", details)
}

func NewInvalidBlockError(details string) error {
	return NewBlockchainError(ErrCodeInvalidBlock, "Invalid Block", details)
}

func NewNetworkFailureError(details string) error {
	return NewBlockchainError(ErrCodeNetworkFailure, "Network Failure", details)
}

func NewInsufficientFundsError(details string) error {
	return NewBlockchainError(ErrCodeInsufficientFunds, "Insufficient Funds", details)
}

func NewUnauthorizedAccessError(details string) error {
	return NewBlockchainError(ErrCodeUnauthorizedAccess, "Unauthorized Access", details)
}

func NewDataCorruptionError(details string) error {
	return NewBlockchainError(ErrCodeDataCorruption, "Data Corruption", details)
}

func NewConsensusFailureError(details string) error {
	return NewBlockchainError(ErrCodeConsensusFailure, "Consensus Failure", details)
}

func NewSmartContractFailureError(details string) error {
	return NewBlockchainError(ErrCodeSmartContractFailure, "Smart Contract Failure", details)
}

// Recovery function for panic situations
func RecoverFromPanic() {
	if r := recover(); r != nil {
		pc, fn, line, _ := runtime.Caller(2)
		errMessage := fmt.Sprintf("[PANIC] %s:%d %s: %v", fn, line, runtime.FuncForPC(pc).Name(), r)
		logToFile(errMessage)
		fmt.Println(errMessage)
	}
}

// Utility functions for error handling in different modules
func HandleTransactionError(txID string, err error) {
	if err != nil {
		LogError(fmt.Errorf("transaction ID %s: %v", txID, err))
	}
}

func HandleBlockError(blockID string, err error) {
	if err != nil {
		LogError(fmt.Errorf("block ID %s: %v", blockID, err))
	}
}

func HandleNetworkError(nodeID string, err error) {
	if err != nil {
		LogError(fmt.Errorf("node ID %s: %v", nodeID, err))
	}
}

func HandleSmartContractError(contractID string, err error) {
	if err != nil {
		LogError(fmt.Errorf("smart contract ID %s: %v", contractID, err))
	}
}

// Example usage for testing purposes
func main() {
	defer RecoverFromPanic()

	// Simulating an invalid transaction error
	txError := NewInvalidTransactionError("Transaction hash mismatch")
	HandleError(txError)

	// Simulating a block error
	blockError := NewInvalidBlockError("Block hash invalid")
	HandleError(blockError)

	// Simulating a network error
	netError := NewNetworkFailureError("Unable to reach consensus node")
	HandleError(netError)

	// Simulating a smart contract failure
	smartContractError := NewSmartContractFailureError("Smart contract execution failed")
	HandleError(smartContractError)
}
package utils

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/utils/logger"
	"github.com/synnergy_network/network/protocol"
)

// LoadBalancer is an interface that defines the methods for a load balancer.
type LoadBalancer interface {
	AddNode(node protocol.Node) error
	RemoveNode(nodeID string) error
	GetNode() (protocol.Node, error)
}

// RoundRobinLoadBalancer is a load balancer that uses the round-robin algorithm.
type RoundRobinLoadBalancer struct {
	nodes []protocol.Node
	mu    sync.Mutex
	index int
}

// NewRoundRobinLoadBalancer creates a new instance of RoundRobinLoadBalancer.
func NewRoundRobinLoadBalancer() *RoundRobinLoadBalancer {
	return &RoundRobinLoadBalancer{
		nodes: make([]protocol.Node, 0),
		index: 0,
	}
}

// AddNode adds a node to the load balancer.
func (lb *RoundRobinLoadBalancer) AddNode(node protocol.Node) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, n := range lb.nodes {
		if n.ID == node.ID {
			return errors.New("node already exists")
		}
	}
	lb.nodes = append(lb.nodes, node)
	return nil
}

// RemoveNode removes a node from the load balancer.
func (lb *RoundRobinLoadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			if lb.index >= len(lb.nodes) {
				lb.index = 0
			}
			return nil
		}
	}
	return errors.New("node not found")
}

// GetNode returns the next node in the round-robin sequence.
func (lb *RoundRobinLoadBalancer) GetNode() (protocol.Node, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.nodes) == 0 {
		return protocol.Node{}, errors.New("no nodes available")
	}
	node := lb.nodes[lb.index]
	lb.index = (lb.index + 1) % len(lb.nodes)
	return node, nil
}

// WeightedLoadBalancer is a load balancer that uses weights to distribute the load.
type WeightedLoadBalancer struct {
	nodes []weightedNode
	mu    sync.Mutex
	total int
}

type weightedNode struct {
	node   protocol.Node
	weight int
}

// NewWeightedLoadBalancer creates a new instance of WeightedLoadBalancer.
func NewWeightedLoadBalancer() *WeightedLoadBalancer {
	return &WeightedLoadBalancer{
		nodes: make([]weightedNode, 0),
		total: 0,
	}
}

// AddNode adds a node with a specific weight to the load balancer.
func (lb *WeightedLoadBalancer) AddNode(node protocol.Node, weight int) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, n := range lb.nodes {
		if n.node.ID == node.ID {
			return errors.New("node already exists")
		}
	}
	lb.nodes = append(lb.nodes, weightedNode{node: node, weight: weight})
	lb.total += weight
	return nil
}

// RemoveNode removes a node from the load balancer.
func (lb *WeightedLoadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.node.ID == nodeID {
			lb.total -= n.weight
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

// GetNode returns a node based on the weighted round-robin algorithm.
func (lb *WeightedLoadBalancer) GetNode() (protocol.Node, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.nodes) == 0 {
		return protocol.Node{}, errors.New("no nodes available")
	}
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(lb.total)
	for _, n := range lb.nodes {
		if r < n.weight {
			return n.node, nil
		}
		r -= n.weight
	}
	return protocol.Node{}, errors.New("unable to select a node")
}

// LeastConnectionLoadBalancer is a load balancer that uses the least connection algorithm.
type LeastConnectionLoadBalancer struct {
	nodes []connNode
	mu    sync.Mutex
}

type connNode struct {
	node        protocol.Node
	connections int
}

// NewLeastConnectionLoadBalancer creates a new instance of LeastConnectionLoadBalancer.
func NewLeastConnectionLoadBalancer() *LeastConnectionLoadBalancer {
	return &LeastConnectionLoadBalancer{
		nodes: make([]connNode, 0),
	}
}

// AddNode adds a node to the load balancer.
func (lb *LeastConnectionLoadBalancer) AddNode(node protocol.Node) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, n := range lb.nodes {
		if n.node.ID == node.ID {
			return errors.New("node already exists")
		}
	}
	lb.nodes = append(lb.nodes, connNode{node: node, connections: 0})
	return nil
}

// RemoveNode removes a node from the load balancer.
func (lb *LeastConnectionLoadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.node.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

// GetNode returns the node with the least number of connections.
func (lb *LeastConnectionLoadBalancer) GetNode() (protocol.Node, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.nodes) == 0 {
		return protocol.Node{}, errors.New("no nodes available")
	}
	minConn := lb.nodes[0].connections
	selectedNode := lb.nodes[0].node
	for _, n := range lb.nodes {
		if n.connections < minConn {
			minConn = n.connections
			selectedNode = n.node
		}
	}
	return selectedNode, nil
}

// IncrementConnections increments the connection count for a node.
func (lb *LeastConnectionLoadBalancer) IncrementConnections(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.node.ID == nodeID {
			lb.nodes[i].connections++
			return nil
		}
	}
	return errors.New("node not found")
}

// DecrementConnections decrements the connection count for a node.
func (lb *LeastConnectionLoadBalancer) DecrementConnections(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.node.ID == nodeID {
			if lb.nodes[i].connections > 0 {
				lb.nodes[i].connections--
			}
			return nil
		}
	}
	return errors.New("node not found")
}

// HealthCheckLoadBalancer is a load balancer that integrates health checks.
type HealthCheckLoadBalancer struct {
	nodes       []protocol.Node
	mu          sync.Mutex
	healthCheck func(protocol.Node) bool
}

// NewHealthCheckLoadBalancer creates a new instance of HealthCheckLoadBalancer.
func NewHealthCheckLoadBalancer(healthCheck func(protocol.Node) bool) *HealthCheckLoadBalancer {
	return &HealthCheckLoadBalancer{
		nodes:       make([]protocol.Node, 0),
		healthCheck: healthCheck,
	}
}

// AddNode adds a node to the load balancer.
func (lb *HealthCheckLoadBalancer) AddNode(node protocol.Node) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, n := range lb.nodes {
		if n.ID == node.ID {
			return errors.New("node already exists")
		}
	}
	lb.nodes = append(lb.nodes, node)
	return nil
}

// RemoveNode removes a node from the load balancer.
func (lb *HealthCheckLoadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, n := range lb.nodes {
		if n.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

// GetNode returns a healthy node.
func (lb *HealthCheckLoadBalancer) GetNode() (protocol.Node, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.nodes) == 0 {
		return protocol.Node{}, errors.New("no nodes available")
	}
	for _, n := range lb.nodes {
		if lb.healthCheck(n) {
			return n, nil
		}
	}
	return protocol.Node{}, errors.New("no healthy nodes available")
}

// MonitorHealth continuously checks the health of nodes in the background.
func (lb *HealthCheckLoadBalancer) MonitorHealth(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		lb.mu.Lock()
		for i, n := range lb.nodes {
			if !lb.healthCheck(n) {
				logger.Warnf("Node %s is unhealthy, removing from load balancer", n.ID)
				lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			}
		}
		lb.mu.Unlock()
	}
}
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/synnergy_network/cryptography/encryption"
	"github.com/synnergy_network/cryptography/hash"
	"github.com/synnergy_network/cryptography/keys"
	"github.com/synnergy_network/network/logger"
	"github.com/synnergy_network/network/p2p/discovery"
	"github.com/synnergy_network/network/protocol"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// ConnectionManager manages network connections.
type ConnectionManager struct {
	connections map[string]net.Conn
	mu          sync.Mutex
}

// NewConnectionManager creates a new ConnectionManager.
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[string]net.Conn),
	}
}

// AddConnection adds a new connection.
func (cm *ConnectionManager) AddConnection(id string, conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connections[id] = conn
}

// RemoveConnection removes an existing connection.
func (cm *ConnectionManager) RemoveConnection(id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if conn, ok := cm.connections[id]; ok {
		conn.Close()
		delete(cm.connections, id)
	}
}

// GetConnection retrieves a connection by ID.
func (cm *ConnectionManager) GetConnection(id string) (net.Conn, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	conn, ok := cm.connections[id]
	if !ok {
		return nil, errors.New("connection not found")
	}
	return conn, nil
}

// SecureCommunication provides methods for encrypted communication.
type SecureCommunication struct {
	key []byte
}

// NewSecureCommunication creates a new SecureCommunication with a given key.
func NewSecureCommunication(password string) (*SecureCommunication, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &SecureCommunication{key: key}, nil
}

// Encrypt encrypts data using AES.
func (sc *SecureCommunication) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES.
func (sc *SecureCommunication) Decrypt(data string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// PeerDiscovery handles peer discovery in the network.
type PeerDiscovery struct {
	peers map[string]protocol.Peer
	mu    sync.Mutex
}

// NewPeerDiscovery creates a new PeerDiscovery instance.
func NewPeerDiscovery() *PeerDiscovery {
	return &PeerDiscovery{
		peers: make(map[string]protocol.Peer),
	}
}

// AddPeer adds a peer to the discovery list.
func (pd *PeerDiscovery) AddPeer(peer protocol.Peer) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.peers[peer.ID] = peer
}

// RemovePeer removes a peer from the discovery list.
func (pd *PeerDiscovery) RemovePeer(peerID string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	delete(pd.peers, peerID)
}

// GetPeer retrieves a peer by ID.
func (pd *PeerDiscovery) GetPeer(peerID string) (protocol.Peer, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	peer, ok := pd.peers[peerID]
	if !ok {
		return protocol.Peer{}, errors.New("peer not found")
	}
	return peer, nil
}

// ListPeers lists all known peers.
func (pd *PeerDiscovery) ListPeers() []protocol.Peer {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	peers := make([]protocol.Peer, 0, len(pd.peers))
	for _, peer := range pd.peers {
		peers = append(peers, peer)
	}
	return peers
}

// NetworkUtils provides various network utilities.
type NetworkUtils struct{}

// NewNetworkUtils creates a new instance of NetworkUtils.
func NewNetworkUtils() *NetworkUtils {
	return &NetworkUtils{}
}

// HashData hashes data using SHA-256.
func (nu *NetworkUtils) HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateKeyPair generates a public-private key pair.
func (nu *NetworkUtils) GenerateKeyPair() (keys.PublicKey, keys.PrivateKey, error) {
	return keys.GenerateKeyPair()
}

// EncryptData encrypts data with a given public key.
func (nu *NetworkUtils) EncryptData(pubKey keys.PublicKey, data []byte) (string, error) {
	encryptedData, err := encryption.Encrypt(pubKey, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedData), nil
}

// DecryptData decrypts data with a given private key.
func (nu *NetworkUtils) DecryptData(privKey keys.PrivateKey, data string) ([]byte, error) {
	encryptedData, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return encryption.Decrypt(privKey, encryptedData)
}

// MonitorNetwork monitors the network for connection issues.
func (nu *NetworkUtils) MonitorNetwork(cm *ConnectionManager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		cm.mu.Lock()
		for id, conn := range cm.connections {
			if err := nu.checkConnection(conn); err != nil {
				logger.Warnf("Connection to %s lost: %v", id, err)
				conn.Close()
				delete(cm.connections, id)
			}
		}
		cm.mu.Unlock()
	}
}

func (nu *NetworkUtils) checkConnection(conn net.Conn) error {
	// Send a ping or similar network check here
	return nil
}

package utils

import (
	"sync"
	"time"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
)

// RateLimiter struct definition
type RateLimiter struct {
	mu             sync.Mutex
	requests       map[string][]time.Time
	limit          int
	windowDuration time.Duration
}

// NewRateLimiter constructor
func NewRateLimiter(limit int, windowDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:       make(map[string][]time.Time),
		limit:          limit,
		windowDuration: windowDuration,
	}
}

// Allow function to check if request is within rate limit
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.windowDuration)

	// Clean up old requests
	requests := rl.requests[clientID]
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}
	rl.requests[clientID] = validRequests

	if len(validRequests) >= rl.limit {
		return false
	}

	// Add the new request
	rl.requests[clientID] = append(rl.requests[clientID], now)
	return true
}

// SecureRateLimiter with encrypted data storage
type SecureRateLimiter struct {
	RateLimiter
	encryptionKey []byte
}

// NewSecureRateLimiter constructor
func NewSecureRateLimiter(limit int, windowDuration time.Duration, encryptionKey string) *SecureRateLimiter {
	key := sha256.Sum256([]byte(encryptionKey))
	return &SecureRateLimiter{
		RateLimiter:   *NewRateLimiter(limit, windowDuration),
		encryptionKey: key[:],
	}
}

// Encrypt data using AES
func (srl *SecureRateLimiter) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(srl.encryptionKey)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt data using AES
func (srl *SecureRateLimiter) Decrypt(encryptedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(srl.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AllowSecure function to check if request is within rate limit and store encrypted data
func (srl *SecureRateLimiter) AllowSecure(clientID string) bool {
	encryptedID, err := srl.Encrypt(clientID)
	if err != nil {
		log.Println("Encryption error:", err)
		return false
	}

	return srl.Allow(encryptedID)
}

// ComprehensiveRateLimiter with additional functionalities
type ComprehensiveRateLimiter struct {
	SecureRateLimiter
	banList    map[string]bool
	banDuration time.Duration
}

// NewComprehensiveRateLimiter constructor
func NewComprehensiveRateLimiter(limit int, windowDuration, banDuration time.Duration, encryptionKey string) *ComprehensiveRateLimiter {
	return &ComprehensiveRateLimiter{
		SecureRateLimiter: *NewSecureRateLimiter(limit, windowDuration, encryptionKey),
		banList:           make(map[string]bool),
		banDuration:       banDuration,
	}
}

// BanClient bans a client for a specific duration
func (crl *ComprehensiveRateLimiter) BanClient(clientID string) error {
	encryptedID, err := crl.Encrypt(clientID)
	if err != nil {
		return err
	}

	crl.banList[encryptedID] = true
	go func() {
		time.Sleep(crl.banDuration)
		crl.mu.Lock()
		delete(crl.banList, encryptedID)
		crl.mu.Unlock()
	}()

	return nil
}

// IsBanned checks if a client is banned
func (crl *ComprehensiveRateLimiter) IsBanned(clientID string) bool {
	encryptedID, err := crl.Encrypt(clientID)
	if err != nil {
		log.Println("Encryption error:", err)
		return false
	}

	crl.mu.Lock()
	defer crl.mu.Unlock()

	return crl.banList[encryptedID]
}

// AllowComprehensive function to check if request is within rate limit and not banned
func (crl *ComprehensiveRateLimiter) AllowComprehensive(clientID string) bool {
	if crl.IsBanned(clientID) {
		return false
	}

	return crl.AllowSecure(clientID)
}

// AdvancedRateLimiter with dynamic rate limits based on client behavior
type AdvancedRateLimiter struct {
	ComprehensiveRateLimiter
	clientBehavior map[string]int
	behaviorLimit  int
}

// NewAdvancedRateLimiter constructor
func NewAdvancedRateLimiter(limit int, windowDuration, banDuration time.Duration, encryptionKey string, behaviorLimit int) *AdvancedRateLimiter {
	return &AdvancedRateLimiter{
		ComprehensiveRateLimiter: *NewComprehensiveRateLimiter(limit, windowDuration, banDuration, encryptionKey),
		clientBehavior:           make(map[string]int),
		behaviorLimit:            behaviorLimit,
	}
}

// RecordBehavior records client behavior to adjust rate limits
func (arl *AdvancedRateLimiter) RecordBehavior(clientID string, behaviorScore int) error {
	encryptedID, err := arl.Encrypt(clientID)
	if err != nil {
		return err
	}

	arl.mu.Lock()
	defer arl.mu.Unlock()

	arl.clientBehavior[encryptedID] += behaviorScore

	if arl.clientBehavior[encryptedID] > arl.behaviorLimit {
		return arl.BanClient(clientID)
	}

	return nil
}

// AdjustRateLimit adjusts the rate limit based on client behavior
func (arl *AdvancedRateLimiter) AdjustRateLimit(clientID string, newLimit int) error {
	encryptedID, err := arl.Encrypt(clientID)
	if err != nil {
		return err
	}

	arl.mu.Lock()
	defer arl.mu.Unlock()

	// Adjusting rate limit for the specific client
	arl.limit = newLimit
	return nil
}

// AllowAdvanced function to check if request is within dynamic rate limit, not banned, and considers behavior
func (arl *AdvancedRateLimiter) AllowAdvanced(clientID string) bool {
	if err := arl.RecordBehavior(clientID, 1); err != nil {
		log.Println("Behavior recording error:", err)
		return false
	}

	return arl.AllowComprehensive(clientID)
}
