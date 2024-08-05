package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// RateLimiter defines the interface for rate limiting mechanisms
type RateLimiter interface {
	AllowRequest(peerID string) bool
	UpdateLimit(peerID string, newLimit int)
}

// AdaptiveRateLimiter implements adaptive rate limiting
type AdaptiveRateLimiter struct {
	mu          sync.Mutex
	limits      map[string]int
	requests    map[string]int
	timestamps  map[string]time.Time
	baseLimit   int
}

// NewAdaptiveRateLimiter creates a new instance of AdaptiveRateLimiter
func NewAdaptiveRateLimiter(baseLimit int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		limits:     make(map[string]int),
		requests:   make(map[string]int),
		timestamps: make(map[string]time.Time),
		baseLimit:  baseLimit,
	}
}

// AllowRequest checks if a request from a peer is allowed based on the current rate limit
func (rl *AdaptiveRateLimiter) AllowRequest(peerID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if lastRequest, exists := rl.timestamps[peerID]; exists {
		if now.Sub(lastRequest) > time.Minute {
			rl.requests[peerID] = 0
			rl.timestamps[peerID] = now
		}
	}

	rl.requests[peerID]++
	if rl.requests[peerID] > rl.getLimit(peerID) {
		return false
	}

	rl.timestamps[peerID] = now
	return true
}

// UpdateLimit updates the rate limit for a specific peer
func (rl *AdaptiveRateLimiter) UpdateLimit(peerID string, newLimit int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limits[peerID] = newLimit
}

// getLimit returns the current rate limit for a peer
func (rl *AdaptiveRateLimiter) getLimit(peerID string) int {
	if limit, exists := rl.limits[peerID]; exists {
		return limit
	}
	return rl.baseLimit
}

// AdjustLimits dynamically adjusts rate limits based on network conditions and peer behavior
func (rl *AdaptiveRateLimiter) AdjustLimits() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for peerID := range rl.limits {
		requests := rl.requests[peerID]
		if requests > rl.baseLimit {
			rl.limits[peerID] = rl.baseLimit / 2
		} else {
			rl.limits[peerID] = rl.baseLimit
		}
	}
}

// LogRateLimiting logs rate limiting events for analysis and audit
func (rl *AdaptiveRateLimiter) LogRateLimiting(peerID string, allowed bool) {
	action := "allowed"
	if !allowed {
		action = "denied"
	}
	log.Printf("Rate limiting %s request from peer %s", action, peerID)
}

// RateLimiterAPI provides an interface for rate limiter operations
type RateLimiterAPI struct {
	limiter *AdaptiveRateLimiter
	mu      sync.Mutex
}

// NewRateLimiterAPI creates a new RateLimiterAPI instance
func NewRateLimiterAPI(baseLimit int) *RateLimiterAPI {
	return &RateLimiterAPI{
		limiter: NewAdaptiveRateLimiter(baseLimit),
	}
}

// RateLimitHandler handles incoming requests and applies rate limiting
func (api *RateLimiterAPI) RateLimitHandler(w http.ResponseWriter, r *http.Request) {
	peerID := r.Header.Get("Peer-ID")
	if peerID == "" {
		http.Error(w, "Peer-ID header missing", http.StatusBadRequest)
		return
	}

	if !api.limiter.AllowRequest(peerID) {
		api.limiter.LogRateLimiting(peerID, false)
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	api.limiter.LogRateLimiting(peerID, true)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request allowed"))
}

// UpdateLimitHandler updates the rate limit for a specific peer
func (api *RateLimiterAPI) UpdateLimitHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		PeerID  string `json:"peer_id"`
		NewLimit int   `json:"new_limit"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if payload.PeerID == "" || payload.NewLimit <= 0 {
		http.Error(w, "Invalid peer_id or new_limit", http.StatusBadRequest)
		return
	}

	api.limiter.UpdateLimit(payload.PeerID, payload.NewLimit)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Rate limit updated"))
}

// MonitorRateLimitingHandler monitors and adjusts rate limits
func (api *RateLimiterAPI) MonitorRateLimitingHandler(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()

	api.limiter.AdjustLimits()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Rate limits adjusted"))
}

// RateLimitConfig represents the configuration for rate limiting
type RateLimitConfig struct {
	BaseLimit          int               `json:"base_limit"`
	PeerSpecificLimits map[string]int    `json:"peer_specific_limits"`
	UpdateInterval     time.Duration     `json:"update_interval"`
	SecurityConfig     SecurityConfig    `json:"security_config"`
}

// SecurityConfig holds the security configurations
type SecurityConfig struct {
	EncryptionMethod string `json:"encryption_method"`
	EncryptionKey    string `json:"encryption_key"`
}

// ConfigManager handles loading and updating the rate limiting configuration
type RateLimitConfigManager struct {
	mu           sync.Mutex
	config       *RateLimitConfig
	configFile   string
	lastModified time.Time
}

// NewConfigManager creates a new ConfigManager
func NewRateLimitConfigManager(configFile string) (*RateLimitConfigManager, error) {
	manager := &ConfigManager{
		configFile: configFile,
	}
	err := manager.loadConfig()
	if err != nil {
		return nil, err
	}
	go manager.watchConfigFile()
	return manager, nil
}

// loadConfig loads the configuration from the file
func (cm *RateLimitConfigManager) loadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	fileInfo, err := os.Stat(cm.configFile)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(cm.lastModified) {
		return nil
	}

	data, err := ioutil.ReadFile(cm.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config RateLimitConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config file: %v", err)
	}

	cm.config = &config
	cm.lastModified = fileInfo.ModTime()
	return nil
}

// watchConfigFile watches the configuration file for changes and reloads it if modified
func (cm *RateLimitConfigManager) WatchConfig() {
	ticker := time.NewTicker(cm.config.UpdateInterval)
	defer ticker.Stop()
	for range ticker.C {
		err := cm.loadRateLimitConfig()
		if err != nil {
			fmt.Printf("Error reloading config: %v\n", err)
		}
	}
}

// GetConfig returns the current configuration
func (cm *RateLimitConfigManager) GetConfig() *RateLimitConfig {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.config
}

// UpdatePeerLimit updates the rate limit for a specific peer
func (cm *RateLimitConfigManager) UpdatePeerLimit(peerID string, newLimit int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return errors.New("configuration not loaded")
	}

	cm.config.PeerSpecificLimits[peerID] = newLimit
	return cm.SaveRateLimitConfig()
}

// saveConfig saves the current configuration to the file
func (cm *RateLimitConfigManager) SaveConfig() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	err = ioutil.WriteFile(cm.configFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	return nil
}

// ValidateSecurityConfig validates the security configurations
func (cm *RateLimitConfigManager) ValidateSecurityConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return errors.New("configuration not loaded")
	}

	// Validate encryption method
	switch cm.config.SecurityConfig.EncryptionMethod {
	case "AES", "Scrypt", "Argon2":
		// valid encryption methods
	default:
		return fmt.Errorf("unsupported encryption method: %s", cm.config.SecurityConfig.EncryptionMethod)
	}

	// Validate encryption key
	if len(cm.config.SecurityConfig.EncryptionKey) == 0 {
		return errors.New("encryption key is empty")
	}

	return nil
}

// SecureEncrypt encrypts data using the specified method and key from the config
func (cm *RateLimitConfigManager) SecureEncrypt(data []byte) ([]byte, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	switch cm.config.SecurityConfig.EncryptionMethod {
	case "AES":
		return AESEncrypt(data, []byte(cm.config.SecurityConfig.EncryptionKey))
	case "Scrypt":
		return ScryptEncrypt(data, []byte(cm.config.SecurityConfig.EncryptionKey))
	case "Argon2":
		return Argon2Encrypt(data, []byte(cm.config.SecurityConfig.EncryptionKey))
	default:
		return nil, fmt.Errorf("unsupported encryption method: %s", cm.config.SecurityConfig.EncryptionMethod)
	}
}

// SecureDecrypt decrypts data using the specified method and key from the config
func (cm *RateLimitConfigManager) SecureDecrypt(encryptedData []byte) ([]byte, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	switch cm.config.SecurityConfig.EncryptionMethod {
	case "AES":
		return AESDecrypt(encryptedData, []byte(cm.config.SecurityConfig.EncryptionKey))
	case "Scrypt":
		return ScryptDecrypt(encryptedData, []byte(cm.config.SecurityConfig.EncryptionKey))
	case "Argon2":
		return Argon2Decrypt(encryptedData, []byte(cm.config.SecurityConfig.EncryptionKey))
	default:
		return nil, fmt.Errorf("unsupported encryption method: %s", cm.config.SecurityConfig.EncryptionMethod)
	}
}

// LogRateLimitingAction logs actions related to rate limiting
func (cm *RateLimitConfigManager) LogRateLimitingAction(action, peerID string, success bool) {
	logStatus := "succeeded"
	if !success {
		logStatus = "failed"
	}
	log.Printf("Rate limiting action %s for peer %s %s\n", action, peerID, logStatus)
}

// AdjustRateLimits dynamically adjusts rate limits based on real-time analysis
func (cm *RateLimitConfigManager) AdjustRateLimits() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Implement logic for dynamically adjusting rate limits
	// Example: Increase base limit if average request count is below threshold
	for peerID, limit := range cm.config.PeerSpecificLimits {
		if limit < cm.config.BaseLimit {
			cm.config.PeerSpecificLimits[peerID] = limit + 1
		}
	}
	cm.saveConfig()
}

// WhitelistBlacklistConfig represents the configuration for whitelisting and blacklisting
type WhitelistBlacklistConfig struct {
	Whitelist      map[string]bool `json:"whitelist"`
	Blacklist      map[string]bool `json:"blacklist"`
	UpdateInterval time.Duration   `json:"update_interval"`
	SecurityConfig SecurityConfig  `json:"security_config"`
}

// ConfigManager handles loading and updating the whitelist and blacklist configuration
type WhitelistBlacklistConfigManager struct {
	mu           sync.Mutex
	config       *WhitelistBlacklistConfig
	configFile   string
	lastModified time.Time
}

// NewConfigManager creates a new ConfigManager
func NewConfigManager(configFile string) (*WhitelistBlacklistConfigManager, error) {
	manager := &WhitelistBlacklistConfigManager{
		configFile: configFile,
	}
	err := manager.LoadWhitelistBlacklistConfig()
	if err != nil {
		return nil, err
	}
	go manager.WatchWhitelistBlacklistConfigFile()
	return manager, nil
}

// loadConfig loads the configuration from the file
func (cm *WhitelistBlacklistConfigManager) LoadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	fileInfo, err := os.Stat(cm.configFile)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %v", err)
	}

	if fileInfo.ModTime().Equal(cm.lastModified) {
		return nil
	}

	data, err := ioutil.ReadFile(cm.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config WhitelistBlacklistConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config file: %v", err)
	}

	cm.config = &config
	cm.lastModified = fileInfo.ModTime()
	return nil
}

// watchConfigFile watches the configuration file for changes and reloads it if modified
func (cm *ConfigManagerWB) WatchConfigFile() {
	ticker := time.NewTicker(cm.config.UpdateInterval)
	for range ticker.C {
		err := cm.loadConfig()
		if err != nil {
			fmt.Printf("Error reloading config: %v\n", err)
		}
	}
}

// GetConfig returns the current configuration
func (cm *WhitelistBlacklistConfigManager) GetConfig() *WhitelistBlacklistConfig {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.config
}

// UpdateWhitelist updates the whitelist
func (cm *WhitelistBlacklistConfigManager) UpdateWhitelist(address string, status bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return errors.New("configuration not loaded")
	}

	cm.config.Whitelist[address] = status
	return cm.SaveWhitelistBlacklistConfig()
}

// UpdateBlacklist updates the blacklist
func (cm *WhitelistBlacklistConfigManager) UpdateBlacklist(address string, status bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return errors.New("configuration not loaded")
	}

	cm.config.Blacklist[address] = status
	return cm.SaveWhitelistBlacklistConfig()
}

// saveConfig saves the current configuration to the file
func (cm *WhitelistBlacklistConfigManager) SaveConfig() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	err = ioutil.WriteFile(cm.configFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	return nil
}

// ValidateSecurityConfig validates the security configurations
func (cm *WhitelistBlacklistConfigManager) ValidateSecurityConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return errors.New("configuration not loaded")
	}

	// Validate encryption method
	switch cm.config.SecurityConfig.EncryptionMethod {
	case "AES", "Scrypt", "Argon2":
		// valid encryption methods
	default:
		return fmt.Errorf("unsupported encryption method: %s", cm.config.SecurityConfig.EncryptionMethod)
	}

	// Validate encryption key
	if len(cm.config.SecurityConfig.EncryptionKey) == 0 {
		return errors.New("encryption key is empty")
	}

	return nil
}

// ConfigureSecurity sets up the security configurations based on the config
func (cm *WhitelistBlacklistConfigManager) ConfigureSecurity() error {
	err := cm.ValidateSecurityConfig()
	if err != nil {
		return err
	}

	// Example of configuring AES encryption
	if cm.config.SecurityConfig.EncryptionMethod == "AES" {
		// Setup AES encryption with the given key
		fmt.Println("Setting up AES encryption")
		// You would typically setup the encryption context here
	}

	// Additional setup for Scrypt or Argon2 can be added here

	return nil
}

// IsWhitelisted checks if an address is whitelisted
func (cm *ConfigManagerWB) IsWhitelisted(address string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return false
	}

	status, exists := cm.config.Whitelist[address]
	return exists && status
}

// IsBlacklisted checks if an address is blacklisted
func (cm *ConfigManagerWB) IsBlacklisted(address string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config == nil {
		return false
	}

	status, exists := cm.config.Blacklist[address]
	return exists && status
}

// RemoveFromWhitelist removes an address from the whitelist
func (cm *ConfigManagerWB) RemoveFromWhitelist(address string) error {
	return cm.UpdateWhitelist(address, false)
}

// RemoveFromBlacklist removes an address from the blacklist
func (cm *ConfigManagerWB) RemoveFromBlacklist(address string) error {
	return cm.UpdateBlacklist(address, false)
}
