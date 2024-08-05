package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/helpers"
)

type Backup struct {
	DataDir         string
	BackupDir       string
	RetentionPeriod time.Duration
}

// Initialize initializes the backup configuration
func (b *Backup) Initialize(dataDir, backupDir string, retentionPeriod time.Duration) {
	b.DataDir = dataDir
	b.BackupDir = backupDir
	b.RetentionPeriod = retentionPeriod
}

// PerformBackup performs the backup of the data directory
func (b *Backup) PerformBackup() error {
	timestamp := time.Now().Format("20060102150405")
	backupPath := filepath.Join(b.BackupDir, fmt.Sprintf("backup_%s", timestamp))

	if err := copyDir(b.DataDir, backupPath); err != nil {
		return fmt.Errorf("failed to perform backup: %v", err)
	}

	log.Printf("Backup completed: %s\n", backupPath)
	return nil
}

// CleanupOldBackups cleans up backups older than the retention period
func (b *Backup) CleanupOldBackups() error {
	files, err := os.ReadDir(b.BackupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			backupPath := filepath.Join(b.BackupDir, file.Name())
			info, err := os.Stat(backupPath)
			if err != nil {
				log.Printf("failed to stat backup path: %v\n", err)
				continue
			}

			if time.Since(info.ModTime()) > b.RetentionPeriod {
				if err := os.RemoveAll(backupPath); err != nil {
					log.Printf("failed to remove old backup: %v\n", err)
				} else {
					log.Printf("Removed old backup: %s\n", backupPath)
				}
			}
		}
	}

	return nil
}

// copyDir copies a directory from src to dst
func copyDir(src string, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src string, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := helpers.CopyBuffer(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

// ScheduleBackups schedules periodic backups based on the provided interval
func (b *Backup) ScheduleBackups(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := b.PerformBackup(); err != nil {
					log.Printf("Error performing backup: %v\n", err)
				}
				if err := b.CleanupOldBackups(); err != nil {
					log.Printf("Error cleaning up old backups: %v\n", err)
				}
			}
		}
	}()
}
