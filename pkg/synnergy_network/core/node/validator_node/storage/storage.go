package storage

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/node/validator_node/helpers"
)

type Storage struct {
	DataDir   string
	LogDir    string
	BackupDir string
	mu        sync.Mutex
}

func (s *Storage) Initialize(dataDir, logDir, backupDir string) {
	s.DataDir = dataDir
	s.LogDir = logDir
	s.BackupDir = backupDir

	if err := s.createDirectories(); err != nil {
		log.Fatalf("failed to create directories: %v", err)
	}
}

func (s *Storage) createDirectories() error {
	dirs := []string{s.DataDir, s.LogDir, s.BackupDir}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Storage) ManageDataReplication() {
	ticker := time.NewTicker(10 * time.Minute)
	for {
		select {
		case <-ticker.C:
			s.replicateData()
		}
	}
}

func (s *Storage) replicateData() {
	// Logic to replicate data to other nodes
	// This is a placeholder function and should include the actual data replication logic
	log.Println("Replicating data to other nodes...")
}

func (s *Storage) BackupData(schedule string, retentionDays int) {
	ticker := time.NewTicker(parseSchedule(schedule))
	for {
		select {
		case <-ticker.C:
			s.performBackup(retentionDays)
		}
	}
}

func (s *Storage) performBackup(retentionDays int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	backupFile := filepath.Join(s.BackupDir, time.Now().Format("20060102_150405")+".zip")
	if err := helpers.ZipDirectory(s.DataDir, backupFile); err != nil {
		log.Printf("failed to backup data: %v", err)
		return
	}
	log.Printf("Backup completed: %s", backupFile)

	s.cleanupOldBackups(retentionDays)
}

func (s *Storage) cleanupOldBackups(retentionDays int) {
	files, err := os.ReadDir(s.BackupDir)
	if err != nil {
		log.Printf("failed to read backup directory: %v", err)
		return
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			log.Printf("failed to get file info: %v", err)
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(s.BackupDir, file.Name()))
			log.Printf("Old backup deleted: %s", file.Name())
		}
	}
}

func (s *Storage) HandleIncomingReplication(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Logic to handle incoming data replication
	// This is a placeholder function and should include the actual logic to handle incoming data
	log.Println("Handling incoming data replication...")
	return nil
}

func parseSchedule(schedule string) time.Duration {
	// This function should parse the schedule string (e.g., "24h", "7d") and return a time.Duration
	// Placeholder implementation for demonstration purposes
	return 24 * time.Hour
}
