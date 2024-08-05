package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// RedundancyBackup handles the creation and management of backup files for data redundancy.
type RedundancyBackup struct {
	primaryPath   string
	backupPath    string
	retentionDays int
}

// NewRedundancyBackup creates a new instance of RedundancyBackup
func NewRedundancyBackup(primaryPath, backupPath string, retentionDays int) *RedundancyBackup {
	return &RedundancyBackup{
		primaryPath:   primaryPath,
		backupPath:    backupPath,
		retentionDays: retentionDays,
	}
}

// CreateBackup creates a backup of the primary database
func (rb *RedundancyBackup) CreateBackup() error {
	currentTime := time.Now().Format("20060102_150405")
	backupFileName := fmt.Sprintf("backup_%s.db", currentTime)
	backupFilePath := filepath.Join(rb.backupPath, backupFileName)

	err := copyFile(rb.primaryPath, backupFilePath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}

	return nil
}

// RestoreBackup restores the latest backup to the primary database path
func (rb *RedundancyBackup) RestoreBackup() error {
	latestBackup, err := rb.getLatestBackup()
	if err != nil {
		return fmt.Errorf("failed to get latest backup: %v", err)
	}

	err = copyFile(latestBackup, rb.primaryPath)
	if err != nil {
		return fmt.Errorf("failed to restore backup: %v", err)
	}

	return nil
}

// PurgeOldBackups removes backups older than the retention period
func (rb *RedundancyBackup) PurgeOldBackups() error {
	files, err := os.ReadDir(rb.backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %v", err)
	}

	cutoffTime := time.Now().AddDate(0, 0, -rb.retentionDays)
	for _, file := range files {
		fileInfo, err := file.Info()
		if err != nil {
			return fmt.Errorf("failed to get file info: %v", err)
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			err := os.Remove(filepath.Join(rb.backupPath, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove old backup: %v", err)
			}
		}
	}

	return nil
}

// getLatestBackup retrieves the latest backup file path
func (rb *RedundancyBackup) getLatestBackup() (string, error) {
	files, err := os.ReadDir(rb.backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to read backup directory: %v", err)
	}

	var latestFile os.DirEntry
	var latestModTime time.Time
	for _, file := range files {
		fileInfo, err := file.Info()
		if err != nil {
			return "", fmt.Errorf("failed to get file info: %v", err)
		}

		if fileInfo.ModTime().After(latestModTime) {
			latestModTime = fileInfo.ModTime()
			latestFile = file
		}
	}

	if latestFile == nil {
		return "", fmt.Errorf("no backups found")
	}

	return filepath.Join(rb.backupPath, latestFile.Name()), nil
}

// copyFile copies a file from source to destination
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}
