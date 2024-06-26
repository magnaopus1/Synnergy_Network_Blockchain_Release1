package logging

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// FilterCriteria represents the criteria for filtering logs
type FilterCriteria struct {
	Severity  []string
	Keywords  []string
	TimeRange TimeRange
}

// TimeRange represents a time range for filtering logs
type TimeRange struct {
	StartTime time.Time
	EndTime   time.Time
}

// LogEntry represents a log entry with detailed information
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Context   string    `json:"context"`
}

// FilterEngine manages the filtering of log entries based on specified criteria
type FilterEngine struct {
	logEntries []LogEntry
	mutex      sync.Mutex
}

// NewFilterEngine initializes a new FilterEngine
func NewFilterEngine() *FilterEngine {
	return &FilterEngine{}
}

// AddLogEntry adds a new log entry to the FilterEngine
func (fe *FilterEngine) AddLogEntry(severity, message, context string) {
	fe.mutex.Lock()
	defer fe.mutex.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Severity:  severity,
		Message:   message,
		Context:   context,
	}
	fe.logEntries = append(fe.logEntries, entry)
	log.Printf("Log entry added: %s - %s", severity, message)
}

// FilterLogs filters log entries based on the provided criteria
func (fe *FilterEngine) FilterLogs(criteria FilterCriteria) []LogEntry {
	fe.mutex.Lock()
	defer fe.mutex.Unlock()

	var filteredLogs []LogEntry
	for _, entry := range fe.logEntries {
		if matchesCriteria(entry, criteria) {
			filteredLogs = append(filteredLogs, entry)
		}
	}

	sort.Slice(filteredLogs, func(i, j int) bool {
		return filteredLogs[i].Timestamp.Before(filteredLogs[j].Timestamp)
	})

	return filteredLogs
}

func matchesCriteria(entry LogEntry, criteria FilterCriteria) bool {
	if len(criteria.Severity) > 0 && !contains(criteria.Severity, entry.Severity) {
		return false
	}
	if len(criteria.Keywords) > 0 && !containsKeywords(entry.Message, criteria.Keywords) {
		return false
	}
	if !criteria.TimeRange.StartTime.IsZero() && entry.Timestamp.Before(criteria.TimeRange.StartTime) {
		return false
	}
	if !criteria.TimeRange.EndTime.IsZero() && entry.Timestamp.After(criteria.TimeRange.EndTime) {
		return false
	}
	return true
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func containsKeywords(message string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(message, keyword) {
			return true
		}
	}
	return false
}

// SaveFilteredLogs saves the filtered logs to a specified file
func (fe *FilterEngine) SaveFilteredLogs(filteredLogs []LogEntry, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}
	defer file.Close()

	for _, entry := range filteredLogs {
		logLine := fmt.Sprintf("%s [%s] %s - %s\n", entry.Timestamp.Format(time.RFC3339), entry.Severity, entry.Context, entry.Message)
		if _, err := file.WriteString(logLine); err != nil {
			return fmt.Errorf("failed to write log entry to file: %v", err)
		}
	}

	log.Printf("Filtered logs saved to %s", filePath)
	return nil
}

// Example usage
func main() {
	engine := NewFilterEngine()

	// Add log entries
	engine.AddLogEntry("INFO", "Blockchain node started", "node1")
	engine.AddLogEntry("ERROR", "Failed to connect to peer", "node1")
	engine.AddLogEntry("DEBUG", "Transaction processed", "node2")

	// Define filter criteria
	criteria := FilterCriteria{
		Severity:  []string{"ERROR", "DEBUG"},
		Keywords:  []string{"connect", "processed"},
		TimeRange: TimeRange{StartTime: time.Now().Add(-1 * time.Hour), EndTime: time.Now()},
	}

	// Filter logs
	filteredLogs := engine.FilterLogs(criteria)

	// Save filtered logs to a file
	err := engine.SaveFilteredLogs(filteredLogs, "./filtered_logs.txt")
	if err != nil {
		log.Fatalf("Failed to save filtered logs: %v", err)
	}
}
