package cloud_deployment

import (
	"context"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/compute/metadata"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// GCPConfig holds configuration details for GCP deployment.
type GCPConfig struct {
	ProjectID           string
	Zone                string
	InstanceName        string
	MachineType         string
	ImageProject        string
	ImageFamily         string
	NetworkName         string
	SubnetworkName      string
	ServiceAccountEmail string
	Tags                []string
	Scopes              []string
	StartupScript       string
}

// NodeDeployment holds the necessary information for deploying a node.
type NodeDeployment struct {
	Config   *GCPConfig
	Compute  *compute.Service
	Context  context.Context
	Network  *compute.Network
	SubNet   *compute.Subnetwork
	Instance *compute.Instance
}

// NewGCPClient initializes a new GCP client.
func NewGCPClient(config *GCPConfig) (*NodeDeployment, error) {
	ctx := context.Background()
	computeService, err := compute.NewService(ctx, option.WithCredentialsFile("path/to/service-account-key.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP compute service: %v", err)
	}

	network, err := getNetwork(computeService, config.ProjectID, config.NetworkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %v", err)
	}

	subnet, err := getSubnetwork(computeService, config.ProjectID, config.NetworkName, config.SubnetworkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get subnet: %v", err)
	}

	return &NodeDeployment{
		Config:  config,
		Compute: computeService,
		Context: ctx,
		Network: network,
		SubNet:  subnet,
	}, nil
}

func getNetwork(computeService *compute.Service, projectID, networkName string) (*compute.Network, error) {
	network, err := computeService.Networks.Get(projectID, networkName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get network: %v", err)
	}
	return network, nil
}

func getSubnetwork(computeService *compute.Service, projectID, networkName, subnetworkName string) (*compute.Subnetwork, error) {
	subnet, err := computeService.Subnetworks.Get(projectID, networkName, subnetworkName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get subnet: %v", err)
	}
	return subnet, nil
}

// CreateInstance creates a VM instance on GCP.
func (nd *NodeDeployment) CreateInstance() error {
	instance := &compute.Instance{
		Name:        nd.Config.InstanceName,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/%s", nd.Config.Zone, nd.Config.MachineType),
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: fmt.Sprintf("projects/%s/global/images/family/%s", nd.Config.ImageProject, nd.Config.ImageFamily),
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				Network:    nd.Network.SelfLink,
				Subnetwork: nd.SubNet.SelfLink,
				AccessConfigs: []*compute.AccessConfig{
					{
						Type: "ONE_TO_ONE_NAT",
						Name: "External NAT",
					},
				},
			},
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email:  nd.Config.ServiceAccountEmail,
				Scopes: nd.Config.Scopes,
			},
		},
		Tags: &compute.Tags{
			Items: nd.Config.Tags,
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "startup-script",
					Value: &nd.Config.StartupScript,
				},
			},
		},
	}

	op, err := nd.Compute.Instances.Insert(nd.Config.ProjectID, nd.Config.Zone, instance).Context(nd.Context).Do()
	if err != nil {
		return fmt.Errorf("failed to create instance: %v", err)
	}

	err = nd.waitForOperation(op)
	if err != nil {
		return fmt.Errorf("failed to wait for operation: %v", err)
	}

	log.Printf("Instance %s created successfully", nd.Config.InstanceName)
	return nil
}

// waitForOperation waits for a GCP operation to complete.
func (nd *NodeDeployment) waitForOperation(op *compute.Operation) error {
	for {
		result, err := nd.Compute.ZoneOperations.Get(nd.Config.ProjectID, nd.Config.Zone, op.Name).Context(nd.Context).Do()
		if err != nil {
			return fmt.Errorf("failed to get operation: %v", err)
		}

		if result.Status == "DONE" {
			if result.Error != nil {
				return fmt.Errorf("operation error: %+v", result.Error.Errors)
			}
			break
		}

		time.Sleep(time.Second)
	}
	return nil
}

// DeployNode orchestrates the entire node deployment process on GCP.
func (nd *NodeDeployment) DeployNode() error {
	err := nd.CreateInstance()
	if err != nil {
		return err
	}

	log.Printf("Node deployed successfully with instance name %s", nd.Config.InstanceName)
	return nil
}

// Main function for demonstration
func main() {
	config := &GCPConfig{
		ProjectID:           "your-project-id",
		Zone:                "us-central1-a",
		InstanceName:        "blockchain-node",
		MachineType:         "n1-standard-1",
		ImageProject:        "debian-cloud",
		ImageFamily:         "debian-10",
		NetworkName:         "default",
		SubnetworkName:      "default",
		ServiceAccountEmail: "your-service-account@your-project.iam.gserviceaccount.com",
		Tags:                []string{"blockchain", "node"},
		Scopes:              []string{"https://www.googleapis.com/auth/cloud-platform"},
		StartupScript:       "#!/bin/bash\nsudo apt-get update && sudo apt-get install -y docker.io",
	}

	deployment, err := NewGCPClient(config)
	if err != nil {
		log.Fatalf("Failed to initialize GCP client: %v", err)
	}

	err = deployment.DeployNode()
	if err != nil {
		log.Fatalf("Failed to deploy node: %v", err)
	}

	log.Println("Node deployment process completed successfully.")
}
