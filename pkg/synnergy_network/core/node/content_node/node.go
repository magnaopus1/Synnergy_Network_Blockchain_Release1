package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
    "sync"

    "github.com/minio/sha256-simd"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
    "golang.org/x/net/context"
    "golang.org/x/sync/semaphore"
    "github.com/ipfs/go-ipfs-api"
)

const (
    maxUploadSize  = 1024 * 1024 * 50 // 50MB
    dataDir        = "./data"
    keyDir         = "./keys"
    publicKeyFile  = "public.pem"
    privateKeyFile = "private.pem"
)

type ContentNode struct {
    storage       *shell.Shell
    uploadSem     *semaphore.Weighted
    downloadSem   *semaphore.Weighted
    encryptionKey *rsa.PrivateKey
    mutex         sync.Mutex
}

func NewContentNode() (*ContentNode, error) {
    storage := shell.NewShell("localhost:5001")
    if !storage.IsUp() {
        return nil, errors.New("IPFS daemon is not running")
    }

    uploadSem := semaphore.NewWeighted(10)
    downloadSem := semaphore.NewWeighted(10)

    privateKey, err := loadOrGeneratePrivateKey()
    if err != nil {
        return nil, err
    }

    return &ContentNode{
        storage:       storage,
        uploadSem:     uploadSem,
        downloadSem:   downloadSem,
        encryptionKey: privateKey,
    }, nil
}

func loadOrGeneratePrivateKey() (*rsa.PrivateKey, error) {
    if _, err := os.Stat(filepath.Join(keyDir, privateKeyFile)); os.IsNotExist(err) {
        privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
        if err != nil {
            return nil, err
        }

        privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
        pemPrivateKey := pem.EncodeToMemory(&pem.Block{
            Type:  "RSA PRIVATE KEY",
            Bytes: privateKeyBytes,
        })

        if err := ioutil.WriteFile(filepath.Join(keyDir, privateKeyFile), pemPrivateKey, 0600); err != nil {
            return nil, err
        }

        publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
        if err != nil {
            return nil, err
        }

        pemPublicKey := pem.EncodeToMemory(&pem.Block{
            Type:  "RSA PUBLIC KEY",
            Bytes: publicKeyBytes,
        })

        if err := ioutil.WriteFile(filepath.Join(keyDir, publicKeyFile), pemPublicKey, 0644); err != nil {
            return nil, err
        }

        return privateKey, nil
    }

    privateKeyBytes, err := ioutil.ReadFile(filepath.Join(keyDir, privateKeyFile))
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(privateKeyBytes)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing private key")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return privateKey, nil
}

func (cn *ContentNode) UploadHandler(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
    if err := r.ParseMultipartForm(maxUploadSize); err != nil {
        http.Error(w, "File too large.", http.StatusBadRequest)
        return
    }

    file, _, err := r.FormFile("uploadFile")
    if err != nil {
        http.Error(w, "Invalid file.", http.StatusBadRequest)
        return
    }
    defer file.Close()

    fileBytes, err := ioutil.ReadAll(file)
    if err != nil {
        http.Error(w, "Could not read file.", http.StatusBadRequest)
        return
    }

    encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &cn.encryptionKey.PublicKey, fileBytes, nil)
    if err != nil {
        http.Error(w, "Failed to encrypt data.", http.StatusInternalServerError)
        return
    }

    if err := cn.uploadSem.Acquire(context.Background(), 1); err != nil {
        http.Error(w, "Server too busy.", http.StatusServiceUnavailable)
        return
    }
    defer cn.uploadSem.Release(1)

    cid, err := cn.storage.Add(bytes.NewReader(encryptedData))
    if err != nil {
        http.Error(w, "Failed to upload to IPFS.", http.StatusInternalServerError)
        return
    }

    w.Write([]byte(fmt.Sprintf("File uploaded successfully: %s", cid)))
}

func (cn *ContentNode) DownloadHandler(w http.ResponseWriter, r *http.Request) {
    cid := r.URL.Query().Get("cid")
    if cid == "" {
        http.Error(w, "CID is required.", http.StatusBadRequest)
        return
    }

    if err := cn.downloadSem.Acquire(context.Background(), 1); err != nil {
        http.Error(w, "Server too busy.", http.StatusServiceUnavailable)
        return
    }
    defer cn.downloadSem.Release(1)

    reader, err := cn.storage.Cat(cid)
    if err != nil {
        http.Error(w, "Failed to retrieve file from IPFS.", http.StatusInternalServerError)
        return
    }
    defer reader.Close()

    encryptedData, err := ioutil.ReadAll(reader)
    if err != nil {
        http.Error(w, "Failed to read file from IPFS.", http.StatusInternalServerError)
        return
    }

    decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, cn.encryptionKey, encryptedData, nil)
    if err != nil {
        http.Error(w, "Failed to decrypt data.", http.StatusInternalServerError)
        return
    }

    w.Write(decryptedData)
}

func (cn *ContentNode) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
    if !cn.storage.IsUp() {
        http.Error(w, "IPFS is not running.", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Content Node is healthy."))
}

func main() {
    cn, err := NewContentNode()
    if err != nil {
        log.Fatalf("Failed to create content node: %v", err)
    }

    http.HandleFunc("/upload", cn.UploadHandler)
    http.HandleFunc("/download", cn.DownloadHandler)
    http.HandleFunc("/health", cn.HealthCheckHandler)

    log.Println("Starting Content Node server on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
