package storage

import (
	"errors"
	"fmt"
	"os"
	"time"
	"io"
)

// BackupManager handles redundancy and backup operations for identity tokens
type BackupManager struct {
	primaryDBPath   string
	backupDBPath    string
	backupFrequency time.Duration
	quit            chan bool
}

// NewBackupManager initializes a new BackupManager
func NewBackupManager(primaryDBPath, backupDBPath string, backupFrequency time.Duration) (*BackupManager, error) {
	manager := &BackupManager{
		primaryDBPath:   primaryDBPath,
		backupDBPath:    backupDBPath,
		backupFrequency: backupFrequency,
		quit:            make(chan bool),
	}

	if err := manager.verifyPaths(); err != nil {
		return nil, err
	}

	go manager.startBackupRoutine()

	return manager, nil
}

// verifyPaths checks if the primary and backup database paths are valid
func (bm *BackupManager) verifyPaths() error {
	if _, err := os.Stat(bm.primaryDBPath); os.IsNotExist(err) {
		return fmt.Errorf("primary database path does not exist: %v", bm.primaryDBPath)
	}

	if err := os.MkdirAll(bm.backupDBPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create backup directory: %v", err)
	}

	return nil
}

// startBackupRoutine initiates the routine to backup the primary database periodically
func (bm *BackupManager) startBackupRoutine() {
	ticker := time.NewTicker(bm.backupFrequency)
	for {
		select {
		case <-ticker.C:
			if err := bm.createBackup(); err != nil {
				fmt.Printf("Backup failed: %v\n", err)
			} else {
				fmt.Println("Backup completed successfully")
			}
		case <-bm.quit:
			ticker.Stop()
			return
		}
	}
}

// createBackup creates a backup of the primary database
func (bm *BackupManager) createBackup() error {
	backupFileName := fmt.Sprintf("backup_%s.db", time.Now().Format("20060102150405"))
	backupFilePath := fmt.Sprintf("%s/%s", bm.backupDBPath, backupFileName)

	sourceFile, err := os.Open(bm.primaryDBPath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(backupFilePath)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

// RestoreBackup restores the database from a specified backup file
func (bm *BackupManager) RestoreBackup(backupFileName string) error {
	backupFilePath := fmt.Sprintf("%s/%s", bm.backupDBPath, backupFileName)

	if _, err := os.Stat(backupFilePath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %v", backupFilePath)
	}

	sourceFile, err := os.Open(backupFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(bm.primaryDBPath)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

// ListBackups lists all backup files available in the backup directory
func (bm *BackupManager) ListBackups() ([]string, error) {
	files, err := os.ReadDir(bm.backupDBPath)
	if err != nil {
		return nil, err
	}

	var backups []string
	for _, file := range files {
		if !file.IsDir() {
			backups = append(backups, file.Name())
		}
	}

	return backups, nil
}

// Stop stops the backup routine
func (bm *BackupManager) Stop() {
	bm.quit <- true
}
