package maintainance

import (
    "fmt"
    "os"
    "runtime"

    "github.com/shirou/gopsutil/cpu"
    "github.com/shirou/gopsutil/disk"
    "github.com/shirou/gopsutil/mem"
    "github.com/synthron_blockchain/crypto/aes"
)

// SystemChecker provides tools to perform various system health checks.
type SystemChecker struct {
    EncryptionKey []byte
}

// NewSystemChecker initializes a new SystemChecker with the necessary dependencies.
func NewSystemChecker(key []byte) *SystemChecker {
    return &SystemChecker{
        EncryptionKey: key,
    }
}

// CheckCPUUsage returns the current CPU usage percentage.
func (sc *SystemChecker) CheckCPUUsage() (float64, error) {
    percentages, err := cpu.Percent(0, false)
    if err != nil {
        return 0, err
    }
    if len(percentages) > 0 {
        return percentages[0], nil
    }
    return 0, fmt.Errorf("could not get CPU usage")
}

// CheckDiskUsage returns the usage statistics of the disk where the root path is located.
func (sc *SystemChecker) CheckDiskUsage() (*disk.UsageStat, error) {
    usage, err := disk.Usage("/")
    if err != nil {
        return nil, err
    }
    return usage, nil
}

// CheckMemoryUsage returns the current memory usage stats.
func (sc *SystemChecker) CheckMemoryUsage() (*mem.VirtualMemoryStat, error) {
    vmStat, err := mem.VirtualMemory()
    if err != nil {
        return nil, err
    }
    return vmStat, nil
}

// EncryptSystemInfo encrypts the system information for secure logging or reporting.
func (sc *SystemChecker) EncryptSystemInfo(info string) ([]byte, error) {
    return aes.Encrypt([]byte(info), sc.EncryptionKey)
}

// ReportSystemHealth collects and reports system health information.
func (sc *SystemChecker) ReportSystemHealth() error {
    cpuUsage, _ := sc.CheckCPUUsage()
    diskUsage, _ := sc.CheckDiskUsage()
    memoryUsage, _ := sc.CheckMemoryUsage()

    report := fmt.Sprintf("CPU Usage: %.2f%%, Disk Used: %dGB Free: %dGB, Memory Used: %dMB Free: %dMB",
        cpuUsage, diskUsage.Used/1024/1024/1024, diskUsage.Free/1024/1024/1024,
        memoryUsage.Used/1024/1024, memoryUsage.Available/1024/1024)

    encryptedReport, err := sc.EncryptSystemInfo(report)
    if err != nil {
        return err
    }

    fmt.Println("Encrypted System Health Report:", encryptedReport)
    return nil
}

func main() {
    // Initialize SystemChecker with a secure key
    key := []byte("your-256-bit-secret") // This key should be securely generated and stored
    checker := NewSystemChecker(key)

    // Example: Running a system health report
    if err := checker.ReportSystemHealth(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to report system health: %s\n", err)
    }
}
