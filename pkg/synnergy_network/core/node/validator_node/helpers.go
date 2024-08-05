package node

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

// GetCPUUsage returns the current CPU usage as a percentage
func GetCPUUsage() float64 {
	percentages, err := cpu.Percent(time.Second, false)
	if err != nil {
		log.Printf("Failed to get CPU usage: %v", err)
		return 0.0
	}
	return percentages[0]
}

// GetMemoryUsage returns the current memory usage as a percentage
func GetMemoryUsage() float64 {
	v, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("Failed to get memory usage: %v", err)
		return 0.0
	}
	return v.UsedPercent
}

// GetDiskUsage returns the current disk usage of the given path as a percentage
func GetDiskUsage(path string) float64 {
	usage, err := disk.Usage(path)
	if err != nil {
		log.Printf("Failed to get disk usage: %v", err)
		return 0.0
	}
	return usage.UsedPercent
}

// GetNetworkLatency measures the latency to a specific host
func GetNetworkLatency(host string) float64 {
	cmd := exec.Command("ping", "-c", "1", host)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to measure network latency: %v", err)
		return 0.0
	}

	// Parse the output to extract the latency
	var latency float64
	_, err = fmt.Sscanf(out.String(), "rtt min/avg/max/mdev = %*f/%f/%*f/%*f ms", &latency)
	if err != nil {
		log.Printf("Failed to parse network latency: %v", err)
		return 0.0
	}

	return latency
}

// GetTransactionsValidated is a placeholder for the actual implementation
func GetTransactionsValidated() int {
	// This should be replaced with the actual logic to get the number of transactions validated
	return 100
}

// GetBlocksCreated is a placeholder for the actual implementation
func GetBlocksCreated() int {
	// This should be replaced with the actual logic to get the number of blocks created
	return 10
}

// ZipDirectory creates a zip archive of the specified directory
func ZipDirectory(source, target string) error {
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	return err
}

// HashData returns the SHA-256 hash of the given data
func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SecureFileEncryption encrypts a file using AES encryption
func SecureFileEncryption(filePath string, key []byte) error {
	// Placeholder implementation - actual AES encryption logic should be implemented
	return nil
}

// SecureFileDecryption decrypts a file using AES encryption
func SecureFileDecryption(filePath string, key []byte) error {
	// Placeholder implementation - actual AES decryption logic should be implemented
	return nil
}

// ValidateSignature validates the digital signature of the given data
func ValidateSignature(data, signature, publicKey []byte) bool {
	// Placeholder implementation - actual signature validation logic should be implemented
	return true
}

// SystemInfo returns system information including OS, architecture, and number of CPUs
func SystemInfo() (string, string, int) {
	return runtime.GOOS, runtime.GOARCH, runtime.NumCPU()
}
