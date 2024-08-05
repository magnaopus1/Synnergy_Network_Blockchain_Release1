package logging_util

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// LogLevel defines the level of logging
type LogLevel int

const (
	// DEBUG level log
	DEBUG LogLevel = iota
	// INFO level log
	INFO
	// WARN level log
	WARN
	// ERROR level log
	ERROR
	// FATAL level log
	FATAL
)

// Logger defines a logger with specific log level and log file
type Logger struct {
	level    LogLevel
	logFile  *os.File
	logger   *log.Logger
	fileName string
}

// NewLogger creates a new Logger instance
func NewLogger(level LogLevel, fileName string) (*Logger, error) {
	logFile, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	return &Logger{
		level:    level,
		logFile:  logFile,
		logger:   log.New(logFile, "", log.LstdFlags),
		fileName: fileName,
	}, nil
}

// Close closes the log file
func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

// log logs a message at the specified level
func (l *Logger) log(level LogLevel, message string) {
	if level >= l.level {
		pc, file, line, ok := runtime.Caller(2)
		if !ok {
			file = "unknown"
			line = 0
		} else {
			fileParts := strings.Split(file, "/")
			file = fileParts[len(fileParts)-1]
		}

		funcName := runtime.FuncForPC(pc).Name()
		logMessage := fmt.Sprintf("[%s] [%s] [%s:%d %s] %s", time.Now().Format(time.RFC3339), levelToString(level), file, line, funcName, message)
		l.logger.Println(logMessage)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	l.log(DEBUG, message)
}

// Info logs an info message
func (l *Logger) Info(message string) {
	l.log(INFO, message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.log(WARN, message)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.log(ERROR, message)
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(message string) {
	l.log(FATAL, message)
	os.Exit(1)
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
