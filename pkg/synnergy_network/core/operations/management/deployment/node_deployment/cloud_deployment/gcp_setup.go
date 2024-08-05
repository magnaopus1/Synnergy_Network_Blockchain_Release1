package cloud_deployment

import (
	"context"
	"log"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// GCPConfig holds configuration details for Google Cloud Platform setup
type GCPConfig struct {
	ProjectID     string
	ServiceAccountKey string
	Region        string
	Zone          string
	MachineType   string
	Network       string
	Subnetwork    string
	Tags          []string
}

// Node represents a compute instance
type Node struct {
	Name   string
	Status string
	IP     string
}

// SetupGCPNode initializes a new node on GCP
func SetupGCPNode(config *GCPConfig, nodeName string) (*Node, error) {
	ctx := context.Background()

	// Authenticate using the service account key
	client, err := compute.NewService(ctx, option.WithCredentialsFile(config.ServiceAccountKey))
	if err != nil {
		log.Fatalf("Failed to create compute service: %v", err)
		return nil, err
	}

	// Define the instance properties
	instance := &compute.Instance{
		Name:        nodeName,
		MachineType: "zones/" + config.Zone + "/machineTypes/" + config.MachineType,
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: "projects/debian-cloud/global/images/family/debian-10",
					DiskSizeGb:  10,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				Network:    "projects/" + config.ProjectID + "/global/networks/" + config.Network,
				Subnetwork: "projects/" + config.ProjectID + "/regions/" + config.Region + "/subnetworks/" + config.Subnetwork,
				AccessConfigs: []*compute.AccessConfig{
					{
						Type: "ONE_TO_ONE_NAT",
						Name: "External NAT",
					},
				},
			},
		},
		Tags: &compute.Tags{
			Items: config.Tags,
		},
	}

	op, err := client.Instances.Insert(config.ProjectID, config.Zone, instance).Context(ctx).Do()
	if err != nil {
		log.Fatalf("Failed to create instance: %v", err)
		return nil, err
	}

	// Wait for the operation to complete
	err = waitForOperation(ctx, client, config.ProjectID, op)
	if err != nil {
		log.Fatalf("Failed to wait for operation: %v", err)
		return nil, err
	}

	// Retrieve the instance details
	inst, err := client.Instances.Get(config.ProjectID, config.Zone, nodeName).Context(ctx).Do()
	if err != nil {
		log.Fatalf("Failed to get instance details: %v", err)
		return nil, err
	}

	node := &Node{
		Name:   inst.Name,
		Status: inst.Status,
		IP:     inst.NetworkInterfaces[0].AccessConfigs[0].NatIP,
	}
	return node, nil
}

// waitForOperation waits for a GCP operation to complete
func waitForOperation(ctx context.Context, client *compute.Service, projectID string, op *compute.Operation) error {
	for op.Status != "DONE" {
		time.Sleep(500 * time.Millisecond)
		var err error
		if op.Zone != "" {
			zone := getResourceName(op.Zone)
			op, err = client.ZoneOperations.Get(projectID, zone, op.Name).Context(ctx).Do()
		} else if op.Region != "" {
			region := getResourceName(op.Region)
			op, err = client.RegionOperations.Get(projectID, region, op.Name).Context(ctx).Do()
		} else {
			op, err = client.GlobalOperations.Get(projectID, op.Name).Context(ctx).Do()
		}
		if err != nil {
			return err
		}
	}
	if op.Error != nil {
		return fmt.Errorf("operation error: %v", op.Error)
	}
	return nil
}

// getResourceName extracts the resource name from its full URL
func getResourceName(resourceURL string) string {
	parts := strings.Split(resourceURL, "/")
	return parts[len(parts)-1]
}

// Authenticate with GCP using service account key
func authenticateWithGCP(serviceAccountKey string) (*storage.Client, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(serviceAccountKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %v", err)
	}
	return client, nil
}

// UploadFile uploads a file to a GCP storage bucket
func UploadFile(client *storage.Client, bucketName, objectName, filePath string) error {
	ctx := context.Background()
	bucket := client.Bucket(bucketName)
	object := bucket.Object(objectName)
	writer := object.NewWriter(ctx)
	defer writer.Close()

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("failed to write file to storage: %v", err)
	}
	return nil
}

// SecureData encrypts data using AES encryption
func SecureData(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES encryption
func DecryptData(ciphertext []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

