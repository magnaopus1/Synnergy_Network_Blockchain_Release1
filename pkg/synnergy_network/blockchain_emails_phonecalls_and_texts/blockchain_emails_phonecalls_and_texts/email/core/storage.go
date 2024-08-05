package core


import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Storage represents the file storage system
type Storage struct {
	baseDir string
}

// NewStorage creates a new Storage instance
func NewStorage(baseDir string) *Storage {
	return &Storage{
		baseDir: baseDir,
	}
}

// Save stores the data in the specified file within the base directory
func (s *Storage) Save(filename string, data interface{}) error {
	filePath := filepath.Join(s.baseDir, filename)
	fileData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, fileData, 0644)
}

// Load retrieves the data from the specified file within the base directory
func (s *Storage) Load(filename string, data interface{}) error {
	filePath := filepath.Join(s.baseDir, filename)
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(fileData, data)
}

// Delete removes the specified file from the base directory
func (s *Storage) Delete(filename string) error {
	filePath := filepath.Join(s.baseDir, filename)
	return os.Remove(filePath)
}

// ListFiles returns a list of all files in the base directory
func (s *Storage) ListFiles() ([]string, error) {
	var files []string
	err := filepath.Walk(s.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, info.Name())
		}
		return nil
	})
	return files, err
}

// MoveFile moves a file from one location to another within the base directory
func (s *Storage) MoveFile(src, dst string) error {
	srcPath := filepath.Join(s.baseDir, src)
	dstPath := filepath.Join(s.baseDir, dst)
	return os.Rename(srcPath, dstPath)
}

// CopyFile copies a file from one location to another within the base directory
func (s *Storage) CopyFile(src, dst string) error {
	srcPath := filepath.Join(s.baseDir, src)
	dstPath := filepath.Join(s.baseDir, dst)

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// FileExists checks if the specified file exists within the base directory
func (s *Storage) FileExists(filename string) bool {
	filePath := filepath.Join(s.baseDir, filename)
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// CreateDirectory creates a new directory within the base directory
func (s *Storage) CreateDirectory(dirname string) error {
	dirPath := filepath.Join(s.baseDir, dirname)
	return os.MkdirAll(dirPath, 0755)
}

// RemoveDirectory removes a directory and its contents within the base directory
func (s *Storage) RemoveDirectory(dirname string) error {
	dirPath := filepath.Join(s.baseDir, dirname)
	return os.RemoveAll(dirPath)
}

// GetFileSize returns the size of the specified file within the base directory
func (s *Storage) GetFileSize(filename string) (int64, error) {
	filePath := filepath.Join(s.baseDir, filename)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

// ReadFile reads the content of the specified file within the base directory
func (s *Storage) ReadFile(filename string) (string, error) {
	filePath := filepath.Join(s.baseDir, filename)
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(fileData), nil
}

// WriteFile writes content to the specified file within the base directory
func (s *Storage) WriteFile(filename, content string) error {
	filePath := filepath.Join(s.baseDir, filename)
	return ioutil.WriteFile(filePath, []byte(content), 0644)
}
