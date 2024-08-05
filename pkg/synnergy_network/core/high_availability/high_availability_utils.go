package utils

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// NewConfigLoader initializes a new ConfigLoader.
func NewConfigLoader() *ConfigLoader {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigLoader{
		ctx:    ctx,
		cancel: cancel,
	}
}

// LoadConfig loads and decrypts the configuration from a file.
func (cl *ConfigLoader) LoadConfig(filePath, password string) error {
	cl.configLock.Lock()
	defer cl.configLock.Unlock()

	// Read encrypted config file
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// Decrypt the configuration data
	configData, err := decryptData(password, encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt config data: %v", err)
	}

	// Unmarshal the JSON configuration data
	var config Config
	err = json.Unmarshal(configData, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config data: %v", err)
	}

	cl.config = &config
	return nil
}

// GetConfig returns the loaded configuration.
func (cl *ConfigLoader) GetConfig() (*Config, error) {
	cl.configLock.Lock()
	defer cl.configLock.Unlock()

	if cl.config == nil {
		return nil, errors.New("configuration not loaded")
	}

	return cl.config, nil
}

// SaveConfig encrypts and saves the configuration to a file.
func (cl *ConfigLoader) SaveConfig(filePath, password string, config *Config) error {
	cl.configLock.Lock()
	defer cl.configLock.Unlock()

	// Marshal the configuration to JSON
	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config data: %v", err)
	}

	// Encrypt the configuration data
	encryptedData, err := encryptData(password, configData)
	if err != nil {
		return fmt.Errorf("failed to encrypt config data: %v", err)
	}

	// Write the encrypted data to the file
	err = os.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// encryptData encrypts data using AES encryption with a key derived from the password.
func encryptData(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// decryptData decrypts data using AES encryption with a key derived from the password.
func decryptData(password string, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// Close stops the ConfigLoader context.
func (cl *ConfigLoader) Close() {
	cl.cancel()
}


// EncryptDataAES encrypts data using AES encryption with a key derived from the password using Scrypt.
func EncryptDataAES(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptDataAES decrypts data using AES encryption with a key derived from the password using Scrypt.
func DecryptDataAES(password string, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Argon2KeyDerivation derives a key using the Argon2id algorithm.
func Argon2KeyDerivation(password, salt string) ([]byte, error) {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return key, nil
}

// EncryptDataArgon2 encrypts data using AES encryption with a key derived from the password using Argon2.
func EncryptDataArgon2(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptDataArgon2 decrypts data using AES encryption with a key derived from the password using Argon2.
func DecryptDataArgon2(password string, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SHA256Hash generates a SHA256 hash of the input data.
func SHA256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SecureRandomBytes generates secure random bytes of a specified length.
func SecureRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// EncryptFile encrypts a file's content and saves the encrypted data to a new file.
func EncryptFile(password, inputFilePath, outputFilePath string, useArgon2 bool) error {
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return err
	}

	var encryptedData []byte
	if useArgon2 {
		encryptedData, err = EncryptDataArgon2(password, data)
	} else {
		encryptedData, err = EncryptDataAES(password, data)
	}
	if err != nil {
		return err
	}

	err = os.WriteFile(outputFilePath, encryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// DecryptFile decrypts a file's content and saves the decrypted data to a new file.
func DecryptFile(password, inputFilePath, outputFilePath string, useArgon2 bool) error {
	encryptedData, err := os.ReadFile(inputFilePath)
	if err != nil {
		return err
	}

	var data []byte
	if useArgon2 {
		data, err = DecryptDataArgon2(password, encryptedData)
	} else {
		data, err = DecryptDataAES(password, encryptedData)
	}
	if err != nil {
		return err
	}

	err = os.WriteFile(outputFilePath, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// EncryptDataWithSalt encrypts data using a provided salt and password with Argon2.
func EncryptDataWithSalt(password, salt string, data []byte) ([]byte, error) {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append([]byte(salt), ciphertext...), nil
}

// DecryptDataWithSalt decrypts data using a provided salt and password with Argon2.
func DecryptDataWithSalt(password string, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, errors.New("encrypted data too short")
	}

	salt := encryptedData[:16]
	data := encryptedData[16:]

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}


// SHA256Hash generates a SHA256 hash of the input data.
func SHA256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SHA512Hash generates a SHA512 hash of the input data.
func SHA512Hash(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// SHA3_256Hash generates a SHA3-256 hash of the input data.
func SHA3_256Hash(data []byte) string {
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SHA3_512Hash generates a SHA3-512 hash of the input data.
func SHA3_512Hash(data []byte) string {
	hash := sha3.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// RIPEMD160Hash generates a RIPEMD-160 hash of the input data.
func RIPEMD160Hash(data []byte) (string, error) {
	hasher := ripemd160.New()
	_, err := hasher.Write(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// DoubleSHA256Hash generates a double SHA256 hash of the input data.
func DoubleSHA256Hash(data []byte) string {
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	return hex.EncodeToString(secondHash[:])
}

// HMACSHA256 generates a HMAC using SHA256.
func HMACSHA256(key, data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// HMACSHA512 generates a HMAC using SHA512.
func HMACSHA512(key, data []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// VerifySHA256Hash verifies that the provided hash matches the SHA256 hash of the input data.
func VerifySHA256Hash(data []byte, hash string) (bool, error) {
	expectedHash := SHA256Hash(data)
	if expectedHash != hash {
		return false, errors.New("hash mismatch")
	}
	return true, nil
}

// VerifySHA512Hash verifies that the provided hash matches the SHA512 hash of the input data.
func VerifySHA512Hash(data []byte, hash string) (bool, error) {
	expectedHash := SHA512Hash(data)
	if expectedHash != hash {
		return false, errors.New("hash mismatch")
	}
	return true, nil
}

// VerifySHA3_256Hash verifies that the provided hash matches the SHA3-256 hash of the input data.
func VerifySHA3_256Hash(data []byte, hash string) (bool, error) {
	expectedHash := SHA3_256Hash(data)
	if expectedHash != hash {
		return false, errors.New("hash mismatch")
	}
	return true, nil
}

// VerifySHA3_512Hash verifies that the provided hash matches the SHA3-512 hash of the input data.
func VerifySHA3_512Hash(data []byte, hash string) (bool, error) {
	expectedHash := SHA3_512Hash(data)
	if expectedHash != hash {
		return false, errors.New("hash mismatch")
	}
	return true, nil
}

// VerifyRIPEMD160Hash verifies that the provided hash matches the RIPEMD-160 hash of the input data.
func VerifyRIPEMD160Hash(data []byte, hash string) (bool, error) {
	expectedHash, err := RIPEMD160Hash(data)
	if err != nil {
		return false, err
	}
	if expectedHash != hash {
		return false, errors.New("hash mismatch")
	}
	return true, nil
}

// NewLogger initializes a new logger instance.
func NewLogger(filePath string, logLevel string, encryption bool, password string) (*Logger, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var key []byte
	var err error
	if encryption {
		key, err = generateKey(password)
		if err != nil {
			return nil, err
		}
	}

	logFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	return &Logger{
		logFile:    logFile,
		ctx:        ctx,
		cancel:     cancel,
		logLevel:   logLevel,
		encryption: encryption,
		key:        key,
	}, nil
}

// Log writes a log message with the given level.
func (l *Logger) Log(level string, message string) {
	if shouldLog(level, l.logLevel) {
		l.mu.Lock()
		defer l.mu.Unlock()

		timestamp := time.Now().Format(time.RFC3339)
		logMessage := fmt.Sprintf("%s [%s]: %s\n", timestamp, level, message)
		if l.encryption {
			encryptedMessage, err := encrypt(logMessage, l.key)
			if err != nil {
				log.Printf("Failed to encrypt log message: %v", err)
				return
			}
			logMessage = encryptedMessage
		}

		_, err := l.logFile.WriteString(logMessage)
		if err != nil {
			log.Printf("Failed to write log message: %v", err)
		}
	}
}

// shouldLog determines if the message should be logged based on the log level.
func shouldLog(level string, configuredLevel string) bool {
	levels := map[string]int{
		DEBUG:   1,
		INFO:    2,
		WARNING: 3,
		ERROR:   4,
	}

	return levels[level] >= levels[configuredLevel]
}

// Close closes the logger and the associated file.
func (l *Logger) Close() {
	l.cancel()
	l.logFile.Close()
}

// RotateLog rotates the log file.
func (l *Logger) RotateLog(newFilePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	oldLogFile := l.logFile
	logFile, err := os.OpenFile(newFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open new log file: %v", err)
	}

	l.logFile = logFile
	oldLogFile.Close()

	return nil
}

// generateKey generates a key for encryption using the provided password.
func generateKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return key, nil
}

// encrypt encrypts the log message using AES.
func encrypt(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts the log message using AES.
func decrypt(encryptedData string, key []byte) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex data: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return string(plaintext), nil
}

// NewMonitoringUtil initializes a new MonitoringUtil instance.
func NewMonitoringUtil() *MonitoringUtil {
	ctx, cancel := context.WithCancel(context.Background())
	return &MonitoringUtil{
		ctx:    ctx,
		cancel: cancel,
		metrics: &SystemMetrics{
			DiskUsage: make(map[string]float64),
		},
		alerts: make(chan string, 100),
	}
}

// StartMonitoring starts the monitoring process.
func (mu *MonitoringUtil) StartMonitoring() {
	go mu.collectMetrics()
	go mu.handleAlerts()
}

// collectMetrics collects system metrics at regular intervals.
func (mu *MonitoringUtil) collectMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mu.ctx.Done():
			return
		case <-ticker.C:
			mu.updateMetrics()
		}
	}
}

// updateMetrics updates the system metrics.
func (mu *MonitoringUtil) updateMetrics() {
	cpuUsage, _ := cpu.Percent(0, false)
	memUsage, _ := mem.VirtualMemory()
	diskUsage, _ := disk.Usage("/")
	networkStats, _ := net.IOCounters(true)

	mu.metricsLock.Lock()
	defer mu.metricsLock.Unlock()

	mu.metrics.CPUUsage = cpuUsage[0]
	mu.metrics.MemoryUsage = memUsage.UsedPercent
	mu.metrics.DiskUsage["/"] = diskUsage.UsedPercent
	mu.metrics.NetworkStats = networkStats
	mu.metrics.Timestamp = time.Now()

	if mu.metrics.CPUUsage > 90 {
		mu.alerts <- fmt.Sprintf("High CPU usage detected: %.2f%%", mu.metrics.CPUUsage)
	}
	if mu.metrics.MemoryUsage > 90 {
		mu.alerts <- fmt.Sprintf("High memory usage detected: %.2f%%", mu.metrics.MemoryUsage)
	}
	if mu.metrics.DiskUsage["/"] > 90 {
		mu.alerts <- fmt.Sprintf("High disk usage detected: %.2f%%", mu.metrics.DiskUsage["/"])
	}
}

// handleAlerts handles alert notifications.
func (mu *MonitoringUtil) handleAlerts() {
	for alert := range mu.alerts {
		// Log alert to console for now, can be extended to send email or other notifications.
		log.Println(alert)
	}
}

// GetMetrics returns the current system metrics.
func (mu *MonitoringUtil) GetMetrics() *SystemMetrics {
	mu.metricsLock.Lock()
	defer mu.metricsLock.Unlock()
	return mu.metrics
}

// ServeMetrics starts an HTTP server to serve metrics data.
func (mu *MonitoringUtil) ServeMetrics(port int) {
	router := mux.NewRouter()
	router.HandleFunc("/metrics", mu.metricsHandler).Methods("GET")
	srv := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf(":%d", port),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on %d: %v\n", port, err)
		}
	}()
}

// metricsHandler handles HTTP requests for metrics data.
func (mu *MonitoringUtil) metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := mu.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Close stops the monitoring process.
func (mu *MonitoringUtil) Close() {
	mu.cancel()
	close(mu.alerts)
}

const (
	NETWORK_TIMEOUT = 5 * time.Second
)

// EncryptData encrypts data using AES encryption with a key derived from the password using Scrypt.
func EncryptData(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES encryption with a key derived from the password using Scrypt.
func DecryptData(password string, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SendData sends data over a TCP connection with encryption.
func SendData(conn net.Conn, password string, data []byte) error {
	encryptedData, err := EncryptData(password, data)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// ReceiveData receives data over a TCP connection with decryption.
func ReceiveData(conn net.Conn, password string) ([]byte, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	data, err := DecryptData(password, buffer[:n])
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ConnectToServer establishes a TCP connection to the specified address with a timeout.
func ConnectToServer(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, NETWORK_TIMEOUT)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenForConnections starts a TCP server that listens for incoming connections on the specified port.
func ListenForConnections(port int, handler func(net.Conn)) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handler(conn)
	}
}

// PingNode sends a ping message to the specified node to check its availability.
func PingNode(address string) error {
	conn, err := ConnectToServer(address)
	if err != nil {
		return err
	}
	defer conn.Close()

	message := []byte("ping")
	err = SendData(conn, "", message)
	if err != nil {
		return err
	}

	response, err := ReceiveData(conn, "")
	if err != nil {
		return err
	}

	if string(response) != "pong" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	return nil
}

// HandlePing handles incoming ping messages and responds with a pong message.
func HandlePing(conn net.Conn) {
	defer conn.Close()

	data, err := ReceiveData(conn, "")
	if err != nil {
		log.Println("Error receiving data:", err)
		return
	}

	if string(data) == "ping" {
		response := []byte("pong")
		err := SendData(conn, "", response)
		if err != nil {
			log.Println("Error sending pong response:", err)
		}
	}
}

// BroadcastMessage sends a message to multiple nodes.
func BroadcastMessage(nodes []string, password string, message []byte) {
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			conn, err := ConnectToServer(node)
			if err != nil {
				log.Println("Error connecting to node:", node, err)
				return
			}
			defer conn.Close()

			err = SendData(conn, password, message)
			if err != nil {
				log.Println("Error sending data to node:", node, err)
			}
		}(node)
	}
	wg.Wait()
}

// NewSnapshotManager initializes a new SnapshotManager instance.
func NewSnapshotManager(snapshotDir, incrementalDir string) (*SnapshotManager, error) {
	if err := os.MkdirAll(snapshotDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %v", err)
	}
	if err := os.MkdirAll(incrementalDir, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create incremental directory: %v", err)
	}
	return &SnapshotManager{
		snapshotDir:    snapshotDir,
		incrementalDir: incrementalDir,
	}, nil
}

// CreateFullSnapshot creates a full snapshot of the current blockchain state.
func (sm *SnapshotManager) CreateFullSnapshot(data []byte) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	snapshotFile := filepath.Join(sm.snapshotDir, fmt.Sprintf("snapshot-%s.dat", timestamp))
	if err := os.WriteFile(snapshotFile, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write snapshot: %v", err)
	}

	sm.currentSnapshot = snapshotFile
	return snapshotFile, nil
}

// CreateIncrementalSnapshot creates an incremental snapshot of the changes since the last snapshot.
func (sm *SnapshotManager) CreateIncrementalSnapshot(changes []byte) (string, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.currentSnapshot == "" {
		return "", fmt.Errorf("no current snapshot available")
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	incrementalFile := filepath.Join(sm.incrementalDir, fmt.Sprintf("incremental-%s.dat", timestamp))
	if err := os.WriteFile(incrementalFile, changes, 0644); err != nil {
		return "", fmt.Errorf("failed to write incremental snapshot: %v", err)
	}

	return incrementalFile, nil
}

// VerifySnapshot verifies the integrity of a snapshot file using SHA-256 hash comparison.
func (sm *SnapshotManager) VerifySnapshot(snapshotFile string, expectedHash string) (bool, error) {
	file, err := os.Open(snapshotFile)
	if err != nil {
		return false, fmt.Errorf("failed to open snapshot file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, fmt.Errorf("failed to hash snapshot file: %v", err)
	}

	actualHash := hex.EncodeToString(hash.Sum(nil))
	return actualHash == expectedHash, nil
}

// ListSnapshots lists all available snapshots and incremental snapshots.
func (sm *SnapshotManager) ListSnapshots() ([]string, []string, error) {
	snapshots, err := filepath.Glob(filepath.Join(sm.snapshotDir, "snapshot-*.dat"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list snapshots: %v", err)
	}

	incrementals, err := filepath.Glob(filepath.Join(sm.incrementalDir, "incremental-*.dat"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list incremental snapshots: %v", err)
	}

	return snapshots, incrementals, nil
}

// RestoreSnapshot restores the blockchain state from a snapshot file.
func (sm *SnapshotManager) RestoreSnapshot(snapshotFile string) ([]byte, error) {
	return os.ReadFile(snapshotFile)
}

// RestoreIncrementalSnapshots applies a series of incremental snapshots to a base snapshot.
func (sm *SnapshotManager) RestoreIncrementalSnapshots(baseSnapshot []byte, incrementalFiles []string) ([]byte, error) {
	state := baseSnapshot
	for _, incrementalFile := range incrementalFiles {
		changes, err := os.ReadFile(incrementalFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read incremental snapshot: %v", err)
		}
		state = applyChanges(state, changes)
	}
	return state, nil
}

// applyChanges applies incremental changes to the blockchain state.
func applyChanges(state []byte, changes []byte) []byte {
	// This is a placeholder for the actual logic to apply changes to the state.
	// Implement the specific logic based on how the blockchain data is structured.
	return append(state, changes...)
}

// ScheduleSnapshots schedules regular snapshots based on a defined interval.
func (sm *SnapshotManager) ScheduleSnapshots(interval time.Duration, getData func() []byte) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		data := getData()
		if _, err := sm.CreateFullSnapshot(data); err != nil {
			log.Printf("Failed to create full snapshot: %v", err)
		}
	}
}

// EncryptSnapshot encrypts the snapshot file using AES encryption.
func (sm *SnapshotManager) EncryptSnapshot(password, snapshotFile string) error {
	data, err := os.ReadFile(snapshotFile)
	if err != nil {
		return fmt.Errorf("failed to read snapshot file: %v", err)
	}

	encryptedData, err := EncryptData(password, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt snapshot file: %v", err)
	}

	return os.WriteFile(snapshotFile, encryptedData, 0644)
}

// DecryptSnapshot decrypts the snapshot file using AES encryption.
func (sm *SnapshotManager) DecryptSnapshot(password, snapshotFile string) error {
	data, err := os.ReadFile(snapshotFile)
	if err != nil {
		return fmt.Errorf("failed to read snapshot file: %v", err)
	}

	decryptedData, err := DecryptData(password, data)
	if err != nil {
		return fmt.Errorf("failed to decrypt snapshot file: %v", err)
	}

	return os.WriteFile(snapshotFile, decryptedData, 0644)
}

// NewStorageUtil initializes a new StorageUtil instance with the specified root directory.
func NewStorageUtil(root string) (*StorageUtil, error) {
	if err := os.MkdirAll(root, os.ModePerm); err != nil {
		return nil, err
	}
	return &StorageUtil{
		root: root,
	}, nil
}

// EncryptData encrypts data using AES with a key derived from the password using Scrypt.
func EncryptData(password string, data []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES with a key derived from the password using Scrypt.
func DecryptData(password string, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}

	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
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

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// WriteFile writes encrypted data to a file.
func (su *StorageUtil) WriteFile(password, filename string, data []byte) error {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	encryptedData, err := EncryptData(password, data)
	if err != nil {
		return err
	}

	filepath := filepath.Join(su.root, filename)
	return ioutil.WriteFile(filepath, encryptedData, 0644)
}

// ReadFile reads and decrypts data from a file.
func (su *StorageUtil) ReadFile(password, filename string) ([]byte, error) {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	filepath := filepath.Join(su.root, filename)
	encryptedData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	return DecryptData(password, encryptedData)
}

// ListFiles lists all files in the storage directory.
func (su *StorageUtil) ListFiles() ([]string, error) {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	var files []string
	err := filepath.Walk(su.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// DeleteFile deletes a file from the storage directory.
func (su *StorageUtil) DeleteFile(filename string) error {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	filepath := filepath.Join(su.root, filename)
	return os.Remove(filepath)
}

// VerifyFileIntegrity verifies the integrity of a file using a provided hash.
func (su *StorageUtil) VerifyFileIntegrity(password, filename, expectedHash string) (bool, error) {
	data, err := su.ReadFile(password, filename)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]) == expectedHash, nil
}

// BackupFiles creates a backup of all files in the storage directory.
func (su *StorageUtil) BackupFiles(password, backupDir string) error {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	if err := os.MkdirAll(backupDir, os.ModePerm); err != nil {
		return err
	}

	files, err := su.ListFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := su.ReadFile(password, file)
		if err != nil {
			return err
		}
		backupPath := filepath.Join(backupDir, file)
		if err := ioutil.WriteFile(backupPath, data, 0644); err != nil {
			return err
		}
	}

	return nil
}

// RestoreFiles restores files from a backup directory.
func (su *StorageUtil) RestoreFiles(password, backupDir string) error {
	su.mutex.Lock()
	defer su.mutex.Unlock()

	files, err := ioutil.ReadDir(backupDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := ioutil.ReadFile(filepath.Join(backupDir, file.Name()))
		if err != nil {
			return err
		}
		if err := su.WriteFile(password, file.Name(), data); err != nil {
			return err
		}
	}

	return nil
}

// NewTimeUtil initializes a new TimeUtil instance
func NewTimeUtil() *TimeUtil {
	return &TimeUtil{}
}

// GetCurrentTime returns the current UTC time
func (tu *TimeUtil) GetCurrentTime() time.Time {
	return time.Now().UTC()
}

// FormatTime formats a given time.Time object into a specified layout
func (tu *TimeUtil) FormatTime(t time.Time, layout string) string {
	return t.Format(layout)
}

// ParseTime parses a string into a time.Time object according to the specified layout
func (tu *TimeUtil) ParseTime(value string, layout string) (time.Time, error) {
	t, err := time.Parse(layout, value)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// AddDuration adds a given duration to a time.Time object
func (tu *TimeUtil) AddDuration(t time.Time, duration time.Duration) time.Time {
	return t.Add(duration)
}

// SubtractDuration subtracts a given duration from a time.Time object
func (tu *TimeUtil) SubtractDuration(t time.Time, duration time.Duration) time.Time {
	return t.Add(-duration)
}

// TimeSince returns the duration since the given time.Time object
func (tu *TimeUtil) TimeSince(t time.Time) time.Duration {
	return time.Since(t)
}

// TimeUntil returns the duration until the given time.Time object
func (tu *TimeUtil) TimeUntil(t time.Time) time.Duration {
	return time.Until(t)
}

// IsBefore checks if a time.Time object is before another time.Time object
func (tu *TimeUtil) IsBefore(t1, t2 time.Time) bool {
	return t1.Before(t2)
}

// IsAfter checks if a time.Time object is after another time.Time object
func (tu *TimeUtil) IsAfter(t1, t2 time.Time) bool {
	return t1.After(t2)
}

// Sleep pauses the execution for a given duration
func (tu *TimeUtil) Sleep(duration time.Duration) {
	time.Sleep(duration)
}

// ScheduleTask schedules a task to run at a specific time
func (tu *TimeUtil) ScheduleTask(runAt time.Time, task func()) error {
	delay := time.Until(runAt)
	if delay <= 0 {
		return errors.New("runAt time must be in the future")
	}
	go func() {
		time.Sleep(delay)
		task()
	}()
	return nil
}

// RepeatedTask schedules a task to run repeatedly at a given interval
func (tu *TimeUtil) RepeatedTask(interval time.Duration, task func()) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			task()
		}
	}()
}

// CompareTimes compares two time.Time objects and returns a TimeComparisonResult
func (tu *TimeUtil) CompareTimes(t1, t2 time.Time) TimeComparisonResult {
	if t1.Equal(t2) {
		return TimeEqual
	} else if t1.Before(t2) {
		return TimeBefore
	}
	return TimeAfter
}

// FormatDuration formats a time.Duration object into a human-readable string
func (tu *TimeUtil) FormatDuration(d time.Duration) string {
	return d.String()
}

// ParseDuration parses a duration string into a time.Duration object
func (tu *TimeUtil) ParseDuration(value string) (time.Duration, error) {
	return time.ParseDuration(value)
}

// GetWeekday returns the weekday of a given time.Time object
func (tu *TimeUtil) GetWeekday(t time.Time) time.Weekday {
	return t.Weekday()
}

// GetStartOfDay returns the start of the day for a given time.Time object
func (tu *TimeUtil) GetStartOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

// GetEndOfDay returns the end of the day for a given time.Time object
func (tu *TimeUtil) GetEndOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 23, 59, 59, 999999999, t.Location())
}

// GetStartOfWeek returns the start of the week (Monday) for a given time.Time object
func (tu *TimeUtil) GetStartOfWeek(t time.Time) time.Time {
	year, week := t.ISOWeek()
	// Go to the first day of the week (Monday)
	return time.Date(year, 0, (week-1)*7+1, 0, 0, 0, 0, t.Location())
}

// GetEndOfWeek returns the end of the week (Sunday) for a given time.Time object
func (tu *TimeUtil) GetEndOfWeek(t time.Time) time.Time {
	startOfWeek := tu.GetStartOfWeek(t)
	return startOfWeek.AddDate(0, 0, 6).Add(time.Hour*23 + time.Minute*59 + time.Second*59 + time.Nanosecond*999999999)
}

// GetStartOfMonth returns the start of the month for a given time.Time object
func (tu *TimeUtil) GetStartOfMonth(t time.Time) time.Time {
	year, month, _ := t.Date()
	return time.Date(year, month, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfMonth returns the end of the month for a given time.Time object
func (tu *TimeUtil) GetEndOfMonth(t time.Time) time.Time {
	startOfMonth := tu.GetStartOfMonth(t)
	return startOfMonth.AddDate(0, 1, -1).Add(time.Hour*23 + time.Minute*59 + time.Second*59 + time.Nanosecond*999999999)
}

// GetStartOfYear returns the start of the year for a given time.Time object
func (tu *TimeUtil) GetStartOfYear(t time.Time) time.Time {
	year := t.Year()
	return time.Date(year, 1, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfYear returns the end of the year for a given time.Time object
func (tu *TimeUtil) GetEndOfYear(t time.Time) time.Time {
	startOfYear := tu.GetStartOfYear(t)
	return startOfYear.AddDate(1, 0, -1).Add(time.Hour*23 + time.Minute*59 + time.Second*59 + time.Nanosecond*999999999)
}
