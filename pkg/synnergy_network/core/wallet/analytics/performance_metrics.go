package analytics

import (
	"fmt"
	"log"
	"time"
	"os"
	"encoding/json"
	"runtime"
	"github.com/pkg/errors"
)

type PerformanceMetrics struct {
	TransactionProcessingTimes []time.Duration
	ResourceUsage              ResourceUsage
}

type ResourceUsage struct {
	CPUUsage    float64
	MemoryUsage uint64
}

type PerformanceLogger struct {
	file *os.File
}

func NewPerformanceLogger(filePath string) (*PerformanceLogger, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open performance log file")
	}
	return &PerformanceLogger{file: file}, nil
}

func (pl *PerformanceLogger) LogMetrics(metrics PerformanceMetrics) error {
	metricsData, err := json.Marshal(metrics)
	if err != nil {
		return errors.Wrap(err, "failed to marshal performance metrics")
	}

	if _, err := pl.file.Write(metricsData); err != nil {
		return errors.Wrap(err, "failed to write performance metrics to log file")
	}

	if _, err := pl.file.WriteString("\n"); err != nil {
		return errors.Wrap(err, "failed to write newline to log file")
	}

	return nil
}

func (pl *PerformanceLogger) Close() error {
	return pl.file.Close()
}

func MeasureTransactionProcessingTime(startTime time.Time, endTime time.Time) time.Duration {
	return endTime.Sub(startTime)
}

func MeasureResourceUsage() ResourceUsage {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	cpuUsage := calculateCPUUsage()

	return ResourceUsage{
		CPUUsage:    cpuUsage,
		MemoryUsage: memStats.Alloc,
	}
}

func calculateCPUUsage() float64 {
	// This is a placeholder. Implementing CPU usage calculation in Go can be complex and often requires
	// platform-specific code or third-party libraries.
	return 0.0
}

func GeneratePerformanceReport(metrics PerformanceMetrics) string {
	report := fmt.Sprintf(
		"Performance Report:\n" +
			"Transaction Processing Times: %v\n" +
			"CPU Usage: %f\n" +
			"Memory Usage: %d\n",
		metrics.TransactionProcessingTimes,
		metrics.ResourceUsage.CPUUsage,
		metrics.ResourceUsage.MemoryUsage,
	)
	return report
}

