package logging

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// LogLevel represents the severity of the log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// StructuredLogger is the core logging structure
type StructuredLogger struct {
	mu           sync.Mutex
	logFile      *os.File
	logLevel     LogLevel
	rotator      *LogRotator
	logDir       string
	logFormat    string
	logStructure LogStructure
	streamer     *RealTimeStreamer
}

// LogStructure defines the structure of the log message
type LogStructure struct {
	Timestamp string    `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Details   LogDetail `json:"details"`
}

// LogDetail represents additional log details
type LogDetail struct {
	FileName string `json:"file_name"`
	Function string `json:"function"`
	Line     int    `json:"line"`
}

// NewStructuredLogger initializes a new StructuredLogger instance
func NewStructuredLogger(logDir, logFileName string, maxSize int64, maxBackups int, logLevel LogLevel, logFormat string, streamer *RealTimeStreamer) (*StructuredLogger, error) {
	rotator, err := NewLogRotator(logDir, logFileName, maxSize, maxBackups)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize LogRotator: %v", err)
	}

	return &StructuredLogger{
		logFile:   rotator.logFile,
		logLevel:  logLevel,
		rotator:   rotator,
		logDir:    logDir,
		logFormat: logFormat,
		streamer:  streamer,
	}, nil
}

// Log writes a structured log message with the specified level and streams it if configured
func (sl *StructuredLogger) Log(level LogLevel, message string, details LogDetail) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if level < sl.logLevel {
		return nil
	}

	timestamp := time.Now().Format(time.RFC3339)
	logEntry := LogStructure{
		Timestamp: timestamp,
		Level:     levelToString(level),
		Message:   message,
		Details:   details,
	}

	logData, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %v", err)
	}

	if err := sl.rotator.WriteLog(string(logData)); err != nil {
		return fmt.Errorf("failed to write log entry: %v", err)
	}

	if sl.streamer != nil {
		sl.streamer.Broadcast(logData)
	}

	return nil
}

// Implement other log level methods: Debug, Info, Warn, Error, Fatal
func (sl *StructuredLogger) Debug(message string, details LogDetail) error {
	return sl.Log(DEBUG, message, details)
}

func (sl *StructuredLogger) Info(message string, details LogDetail) error {
	return sl.Log(INFO, message, details)
}

func (sl *StructuredLogger) Warn(message string, details LogDetail) error {
	return sl.Log(WARN, message, details)
}

func (sl *StructuredLogger) Error(message string, details LogDetail) error {
	return sl.Log(ERROR, message, details)
}

func (sl *StructuredLogger) Fatal(message string, details LogDetail) error {
	return sl.Log(FATAL, message, details)
}

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

func (sl *StructuredLogger) Rotate() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.rotator.rotate()
}

func (sl *StructuredLogger) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.rotator.Close()
}

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

// LogRotator manages log rotation and retention
type LogRotator struct {
	mu         sync.Mutex
	logFile    *os.File
	logDir     string
	logFileName string
	maxSize    int64
	maxBackups int
	currentSize int64
}

func NewLogRotator(logDir, logFileName string, maxSize int64, maxBackups int) (*LogRotator, error) {
	logFilePath := filepath.Join(logDir, logFileName)
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	info, err := logFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat log file: %v", err)
	}

	return &LogRotator{
		logFile:     logFile,
		logDir:      logDir,
		logFileName: logFileName,
		maxSize:     maxSize,
		maxBackups:  maxBackups,
		currentSize: info.Size(),
	}, nil
}

func (lr *LogRotator) WriteLog(data string) error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	dataSize := int64(len(data))
	if lr.currentSize+dataSize > lr.maxSize {
		if err := lr.rotate(); err != nil {
			return err
		}
	}

	_, err := lr.logFile.WriteString(data + "\n")
	if err != nil {
		return err
	}

	lr.currentSize += dataSize
	return nil
}

func (lr *LogRotator) rotate() error {
	if err := lr.logFile.Close(); err != nil {
		return err
	}

	for i := lr.maxBackups - 1; i >= 0; i-- {
		oldPath := filepath.Join(lr.logDir, fmt.Sprintf("%s.%d", lr.logFileName, i))
		newPath := filepath.Join(lr.logDir, fmt.Sprintf("%s.%d", lr.logFileName, i+1))
		if i == 0 {
			oldPath = filepath.Join(lr.logDir, lr.logFileName)
		}

		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
		}
	}

	logFilePath := filepath.Join(lr.logDir, lr.logFileName)
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	lr.logFile = logFile
	lr.currentSize = 0
	return nil
}

func (lr *LogRotator) Close() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.logFile.Close()
}

func main() {
	logDir := "./logs"
	logFileName := "synthron.log"
	maxSize := int64(10 * 1024 * 1024) // 10 MB
	maxBackups := 5
	logLevel := INFO
	logFormat := "json"
	streamer := NewRealTimeStreamer()

	logger, err := NewStructuredLogger(logDir, logFileName, maxSize, maxBackups, logLevel, logFormat, streamer)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}
	defer logger.Close()

	details := LogDetail{
		FileName: "example.go",
		Function: "main",
		Line:     100,
	}

	logger.Info("This is an info message", details)
	logger.Warn("This is a warning message", details)
	logger.Error("This is an error message", details)

	encryptedData, err := EncryptLogData([]byte("Sensitive log data"), "password123")
	if err != nil {
		fmt.Printf("Failed to encrypt data: %v\n", err)
		return
	}

	fmt.Printf("Encrypted data: %x\n", encryptedData)

	decryptedData, err := DecryptLogData(encryptedData, "password123")
	if err != nil {
		fmt.Printf("Failed to decrypt data: %v\n", err)
		return
	}

	fmt.Printf("Decrypted data: %s\n", decryptedData)
}
