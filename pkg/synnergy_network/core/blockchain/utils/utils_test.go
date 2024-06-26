package utils

import (
	"bytes"
	"log"
	"os"
	"testing"
)

// TestLogLevel tests the setting and getting of log levels.
func TestLogLevel(t *testing.T) {
	logger, err := NewLogger(DEBUG, "test.log")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer os.Remove("test.log")
	defer logger.Close()

	if logger.level != DEBUG {
		t.Errorf("Expected log level %d, got %d", DEBUG, logger.level)
	}

	logger.SetLogLevel(INFO)
	if logger.level != INFO {
		t.Errorf("Expected log level %d, got %d", INFO, logger.level)
	}
}

// TestLogging tests the logging functionality at different levels.
func TestLogging(t *testing.T) {
	logger, err := NewLogger(DEBUG, "test.log")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer os.Remove("test.log")
	defer logger.Close()

	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Warn("Warning message")
	logger.Error("Error message")

	file, err := os.Open("test.log")
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	logContents := buf.String()

	expectedMessages := []string{
		"DEBUG: Debug message",
		"INFO: Info message",
		"WARN: Warning message",
		"ERROR: Error message",
	}

	for _, msg := range expectedMessages {
		if !contains(logContents, msg) {
			t.Errorf("Expected log message '%s' not found in log file", msg)
		}
	}
}

// contains checks if the substring is present in the string.
func contains(str, substr string) bool {
	return bytes.Contains([]byte(str), []byte(substr))
}

// TestFatalLogging tests the fatal logging functionality.
func TestFatalLogging(t *testing.T) {
	logger, err := NewLogger(DEBUG, "test.log")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer os.Remove("test.log")
	defer logger.Close()

	// Capture os.Exit calls
	exitCalled := false
	osExit = func(code int) {
		exitCalled = true
	}

	logger.Fatal("Fatal message")

	if !exitCalled {
		t.Errorf("Expected os.Exit to be called, but it wasn't")
	}

	file, err := os.Open("test.log")
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	logContents := buf.String()

	expectedMessage := "FATAL: Fatal message"

	if !contains(logContents, expectedMessage) {
		t.Errorf("Expected log message '%s' not found in log file", expectedMessage)
	}
}

// osExit is a variable to allow mocking of os.Exit in tests.
var osExit = os.Exit

// TestConcurrentLogging tests the logger's ability to handle concurrent logging.
func TestConcurrentLogging(t *testing.T) {
	logger, err := NewLogger(DEBUG, "test.log")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer os.Remove("test.log")
	defer logger.Close()

	// Perform concurrent logging
	concurrentLogs := 100
	done := make(chan bool)

	for i := 0; i < concurrentLogs; i++ {
		go func(i int) {
			logger.Debug("Debug message %d", i)
			logger.Info("Info message %d", i)
			logger.Warn("Warning message %d", i)
			logger.Error("Error message %d", i)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrentLogs; i++ {
		<-done
	}

	file, err := os.Open("test.log")
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	logContents := buf.String()

	for i := 0; i < concurrentLogs; i++ {
		expectedMessages := []string{
			"DEBUG: Debug message %d",
			"INFO: Info message %d",
			"WARN: Warning message %d",
			"ERROR: Error message %d",
		}

		for _, msg := range expectedMessages {
			if !contains(logContents, fmt.Sprintf(msg, i)) {
				t.Errorf("Expected log message '%s' not found in log file", fmt.Sprintf(msg, i))
			}
		}
	}
}
