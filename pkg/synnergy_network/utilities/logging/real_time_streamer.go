package logging

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RealTimeStreamer is responsible for real-time log streaming
type RealTimeStreamer struct {
	mu          sync.Mutex
	upgrader    websocket.Upgrader
	connections map[*websocket.Conn]bool
	broadcast   chan []byte
}

// NewRealTimeStreamer initializes a new RealTimeStreamer instance
func NewRealTimeStreamer() *RealTimeStreamer {
	return &RealTimeStreamer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		connections: make(map[*websocket.Conn]bool),
		broadcast:   make(chan []byte),
	}
}

// ServeHTTP handles incoming websocket requests
func (rts *RealTimeStreamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := rts.upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Fprintf(w, "Failed to upgrade to websocket: %v", err)
		return
	}

	rts.mu.Lock()
	rts.connections[conn] = true
	rts.mu.Unlock()

	go rts.handleMessages(conn)
}

// handleMessages reads messages from the websocket connection
func (rts *RealTimeStreamer) handleMessages(conn *websocket.Conn) {
	defer func() {
		rts.mu.Lock()
		delete(rts.connections, conn)
		rts.mu.Unlock()
		conn.Close()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		rts.broadcast <- message
	}
}

// Broadcast sends a message to all connected clients
func (rts *RealTimeStreamer) Broadcast(message []byte) {
	rts.mu.Lock()
	defer rts.mu.Unlock()

	for conn := range rts.connections {
		err := conn.WriteMessage(websocket.TextMessage, message)
		if err != nil {
			conn.Close()
			delete(rts.connections, conn)
		}
	}
}

// Start starts the real-time streaming server
func (rts *RealTimeStreamer) Start(addr string) {
	http.Handle("/stream", rts)
	go func() {
		for {
			message := <-rts.broadcast
			rts.Broadcast(message)
		}
	}()
	http.ListenAndServe(addr, nil)
}

// LoggerCore extended to support real-time streaming
type LoggerCore struct {
	mu          sync.Mutex
	logFile     *os.File
	logLevel    LogLevel
	rotator     *LogRotator
	logDir      string
	logFormat   string
	streamer    *RealTimeStreamer
}

// NewLoggerCore initializes a new LoggerCore instance
func NewLoggerCore(logDir, logFileName string, maxSize int64, maxBackups int, logLevel LogLevel, logFormat string, streamer *RealTimeStreamer) (*LoggerCore, error) {
	rotator, err := NewLogRotator(logDir, logFileName, maxSize, maxBackups)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LogRotator: %v", err)
	}

	return &LoggerCore{
		logFile:   rotator.logFile,
		logLevel:  logLevel,
		rotator:   rotator,
		logDir:    logDir,
		logFormat: logFormat,
		streamer:  streamer,
	}, nil
}

// Log writes a log message with the specified level and streams it if configured
func (lc *LoggerCore) Log(level LogLevel, message string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if level < lc.logLevel {
		return nil
	}

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf(lc.logFormat, timestamp, levelToString(level), message)

	if err := lc.rotator.WriteLog(logEntry); err != nil {
		return fmt.Errorf("failed to write log entry: %v", err)
	}

	if lc.streamer != nil {
		lc.streamer.Broadcast([]byte(logEntry))
	}

	return nil
}

// Implement other log level methods: Debug, Info, Warn, Error, Fatal
// Debug logs a message at the DEBUG level
func (lc *LoggerCore) Debug(message string) error {
	return lc.Log(DEBUG, message)
}

// Info logs a message at the INFO level
func (lc *LoggerCore) Info(message string) error {
	return lc.Log(INFO, message)
}

// Warn logs a message at the WARN level
func (lc *LoggerCore) Warn(message string) error {
	return lc.Log(WARN, message)
}

// Error logs a message at the ERROR level
func (lc *LoggerCore) Error(message string) error {
	return lc.Log(ERROR, message)
}

// Fatal logs a message at the FATAL level
func (lc *LoggerCore) Fatal(message string) error {
	return lc.Log(FATAL, message)
}

// levelToString converts a LogLevel to its string representation
func levelToString(level LogLevel) string {
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

// Rotate manually forces a log rotation
func (lc *LoggerCore) Rotate() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	return lc.rotator.rotate()
}

// Close closes the LoggerCore instance
func (lc *LoggerCore) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.rotator.Close()
}

// EncryptLogData encrypts log data using scrypt and AES
func EncryptLogData(data []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
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
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptLogData decrypts log data using scrypt and AES
func DecryptLogData(data []byte, password string) ([]byte, error) {
	salt := data[:16]
	data = data[16:]

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
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
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Example usage
func main() {
	logDir := "./logs"
	logFileName := "synthron.log"
	maxSize := int64(10 * 1024 * 1024) // 10 MB
	maxBackups := 5
	logLevel := INFO
	logFormat := "[%s] [%s] %s\n" // timestamp, level, message

	streamer := NewRealTimeStreamer()
	go streamer.Start(":8080")

	logger, err := NewLoggerCore(logDir, logFileName, maxSize, maxBackups, logLevel, logFormat, streamer)
	if err != nil {
		fmt.Printf("Failed to initialize LoggerCore: %v\n", err)
		return
	}
	defer logger.Close()

	logger.Info("This is an info message")
	logger.Debug("This is a debug message")
	logger.Warn("This is a warning message")
	logger.Error("This is an error message")
	logger.Fatal("This is a fatal message")

	// Manually rotate logs
	if err := logger.Rotate(); err != nil {
		fmt.Printf("Failed to rotate logs: %v\n", err)
	}

	// Encrypt and Decrypt example
	data := []byte("Sensitive log data")
	password := "strongpassword"

	encryptedData, err := EncryptLogData(data, password)
	if err != nil {
		fmt.Printf("Failed to encrypt data: %v\n", err)
		return
	}

	decryptedData, err := DecryptLogData(encryptedData, password)
	if err != nil {
		fmt.Printf("Failed to decrypt data: %v\n", err)
		return
	}

	fmt.Printf("Decrypted data: %s\n", decryptedData)
}
