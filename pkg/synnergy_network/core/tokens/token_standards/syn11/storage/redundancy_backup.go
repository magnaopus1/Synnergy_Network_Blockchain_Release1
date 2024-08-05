package storage

import (
	"errors"
	"fmt"
	"os"
	"time"
	"io"
)

// RedundancyBackupManager handles the redundancy and backup of critical data.
type RedundancyBackupManager struct {
	PrimaryDBPath   string
	BackupDBPaths   []string
	BackupFrequency time.Duration
}

// NewRedundancyBackupManager initializes a new RedundancyBackupManager.
func NewRedundancyBackupManager(primaryDBPath string, backupDBPaths []string, backupFrequency time.Duration) *RedundancyBackupManager {
	return &RedundancyBackupManager{
		PrimaryDBPath:   primaryDBPath,
		BackupDBPaths:   backupDBPaths,
		BackupFrequency: backupFrequency,
	}
}

// PerformBackup performs backup operations to all specified backup paths.
func (rbm *RedundancyBackupManager) PerformBackup() error {
	for _, backupPath := range rbm.BackupDBPaths {
		if err := rbm.backupToPath(backupPath); err != nil {
			return fmt.Errorf("backup to %s failed: %w", backupPath, err)
		}
	}
	return nil
}

// backupToPath handles the actual copying of the primary database file to a backup location.
func (rbm *RedundancyBackupManager) backupToPath(backupPath string) error {
	sourceFile, err := os.Open(rbm.PrimaryDBPath)
	if err != nil {
		return fmt.Errorf("failed to open primary database file: %w", err)
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupFile.Close()

	_, err = io.Copy(backupFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy data to backup file: %w", err)
	}

	return nil
}

// ScheduleRegularBackups schedules regular backups based on the specified frequency.
func (rbm *RedundancyBackupManager) ScheduleRegularBackups() {
	ticker := time.NewTicker(rbm.BackupFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := rbm.PerformBackup(); err != nil {
				fmt.Printf("Backup failed: %s\n", err)
			} else {
				fmt.Println("Backup completed successfully.")
			}
		}
	}
}

// VerifyBackupIntegrity checks the integrity of the backup files.
func (rbm *RedundancyBackupManager) VerifyBackupIntegrity() error {
	for _, backupPath := range rbm.BackupDBPaths {
		if _, err := os.Stat(backupPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("backup file %s does not exist", backupPath)
		}
		// Additional checks can include hash verification, file size comparison, etc.
	}
	return nil
}

// RestoreFromBackup restores the primary database from the latest backup.
func (rbm *RedundancyBackupManager) RestoreFromBackup() error {
	if len(rbm.BackupDBPaths) == 0 {
		return errors.New("no backup paths configured")
	}

	// Assuming the first path is the most recent backup
	backupPath := rbm.BackupDBPaths[0]

	sourceFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(rbm.PrimaryDBPath)
	if err != nil {
		return fmt.Errorf("failed to create primary database file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to restore data from backup: %w", err)
	}

	return nil
}

// DeleteOldBackups deletes backup files older than a specified duration.
func (rbm *RedundancyBackupManager) DeleteOldBackups(maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)

	for _, backupPath := range rbm.BackupDBPaths {
		fileInfo, err := os.Stat(backupPath)
		if err != nil {
			return fmt.Errorf("failed to stat backup file: %w", err)
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			if err := os.Remove(backupPath); err != nil {
				return fmt.Errorf("failed to delete old backup file %s: %w", backupPath, err)
			}
			fmt.Printf("Deleted old backup file: %s\n", backupPath)
		}
	}
	return nil
}
