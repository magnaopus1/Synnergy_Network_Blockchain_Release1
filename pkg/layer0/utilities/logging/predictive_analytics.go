package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/teststorage"
	"golang.org/x/crypto/scrypt"
)

// LogLevel defines the level of logging
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// LoggerCore is the core logging structure for the Synthron blockchain
type LoggerCore struct {
	mu        sync.Mutex
	logFile   *os.File
	logLevel  LogLevel
	rotator   *LogRotator
	logDir    string
	logFormat string
}

// NewLoggerCore initializes a new LoggerCore instance
func NewLoggerCore(logDir, logFileName string, maxSize int64, maxBackups int, logLevel LogLevel, logFormat string) (*LoggerCore, error) {
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
	}, nil
}

// Log writes a log message with the specified level
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

	return nil
}

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

// Rotate logs manually forces a log rotation
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

// PredictiveAnalytics implements the predictive analytics logic
type PredictiveAnalytics struct {
	mu           sync.Mutex
	storage      storage.Storage
	engine       *promql.Engine
	queryHistory []string
}

// NewPredictiveAnalytics initializes a new PredictiveAnalytics instance
func NewPredictiveAnalytics() (*PredictiveAnalytics, error) {
	storage := teststorage.New(t)
	engine := promql.NewEngine(promql.EngineOpts{
		Logger:     nil,
		Reg:        nil,
		MaxSamples: 50000000,
		Timeout:    time.Minute,
	})

	return &PredictiveAnalytics{
		storage: storage,
		engine:  engine,
	}, nil
}

// AnalyzeLogData performs predictive analytics on log data
func (pa *PredictiveAnalytics) AnalyzeLogData(query string) (model.Vector, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	now := time.Now()
	q, err := pa.engine.NewInstantQuery(pa.storage, query, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create query: %v", err)
	}

	res := q.Exec()
	if res.Err != nil {
		return nil, fmt.Errorf("query execution failed: %v", res.Err)
	}

	if res.Value.Type() != model.ValVector {
		return nil, fmt.Errorf("unexpected result type: %v", res.Value.Type())
	}

	return res.Value.(model.Vector), nil
}

// StoreQuery stores a query for future analysis
func (pa *PredictiveAnalytics) StoreQuery(query string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	pa.queryHistory = append(pa.queryHistory, query)
}

// GetStoredQueries returns the stored queries
func (pa *PredictiveAnalytics) GetStoredQueries() []string {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	return pa.queryHistory
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

	logger, err := NewLoggerCore(logDir, logFileName, maxSize, maxBackups, logLevel, logFormat)
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

	// Predictive Analytics
	pa, err := NewPredictiveAnalytics()
	if err != nil {
		fmt.Printf("Failed to initialize PredictiveAnalytics: %v\n", err)
		return
	}

	query := `rate(log_entries_total[5m])`
	result, err := pa.AnalyzeLogData(query)
	if err != nil {
		fmt.Printf("Failed to analyze log data: %v\n", err)
		return
	}

	fmt.Printf("Predictive analysis result: %v\n", result)
}
