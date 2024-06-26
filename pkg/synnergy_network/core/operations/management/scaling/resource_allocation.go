package scaling

import (
	"context"
	"log"
	"sync"
	"time"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"cloud.google.com/go/compute/metadata"
	"google.golang.org/api/compute/v1"
)

// ResourceAllocator manages resource allocation for blockchain nodes
type ResourceAllocator struct {
	minNodes        int
	maxNodes        int
	cpuThreshold    float64
	memThreshold    float64
	allocationInterval time.Duration
	awsSession      *session.Session
	googleClient    *compute.Service
	nodes           []string
	mutex           sync.Mutex
}

// NewResourceAllocator initializes a new ResourceAllocator instance
func NewResourceAllocator(minNodes, maxNodes int, cpuThreshold, memThreshold float64, allocationInterval time.Duration) (*ResourceAllocator, error) {
	awsSess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create AWS session")
	}

	googleClient, err := compute.NewService(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Google compute client")
	}

	return &ResourceAllocator{
		minNodes:        minNodes,
		maxNodes:        maxNodes,
		cpuThreshold:    cpuThreshold,
		memThreshold:    memThreshold,
		allocationInterval: allocationInterval,
		awsSession:      awsSess,
		googleClient:    googleClient,
	}, nil
}

// MonitorAndAllocate monitors the network and allocates resources based on predefined thresholds
func (r *ResourceAllocator) MonitorAndAllocate(ctx context.Context) {
	ticker := time.NewTicker(r.allocationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.allocateResources()
		}
	}
}

// allocateResources adjusts the number of active nodes based on CPU and memory usage
func (r *ResourceAllocator) allocateResources() {
	cpuUsage, memUsage, err := r.collectMetrics()
	if err != nil {
		log.Println("Error collecting metrics: ", err)
		return
	}

	if cpuUsage > r.cpuThreshold || memUsage > r.memThreshold {
		r.scaleUp()
	} else {
		r.scaleDown()
	}
}

// collectMetrics collects CPU and memory usage metrics from nodes
func (r *ResourceAllocator) collectMetrics() (float64, float64, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var totalCPUUsage, totalMemUsage float64
	var nodeCount int

	for _, node := range r.nodes {
		cpuUsage, memUsage := getNodeMetrics(node)
		totalCPUUsage += cpuUsage
		totalMemUsage += memUsage
		nodeCount++
	}

	if nodeCount == 0 {
		return 0, 0, errors.New("no nodes available for metric collection")
	}

	avgCPUUsage := totalCPUUsage / float64(nodeCount)
	avgMemUsage := totalMemUsage / float64(nodeCount)

	return avgCPUUsage, avgMemUsage, nil
}

// getNodeMetrics simulates getting metrics from a node
func getNodeMetrics(node string) (float64, float64) {
	// This should be replaced with actual logic to collect metrics from nodes
	return 50.0, 60.0 // Simulated CPU and memory usage
}

// scaleUp increases the number of active nodes
func (r *ResourceAllocator) scaleUp() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if len(r.nodes) >= r.maxNodes {
		log.Println("Max nodes reached, cannot scale up further")
		return
	}

	newNode, err := r.addNode()
	if err != nil {
		log.Println("Error scaling up: ", err)
		return
	}

	r.nodes = append(r.nodes, newNode)
	log.Printf("Scaled up, new node added: %s, total nodes: %d\n", newNode, len(r.nodes))
}

// scaleDown decreases the number of active nodes
func (r *ResourceAllocator) scaleDown() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if len(r.nodes) <= r.minNodes {
		log.Println("Min nodes reached, cannot scale down further")
		return
	}

	nodeToRemove := r.nodes[len(r.nodes)-1]
	if err := r.removeNode(nodeToRemove); err != nil {
		log.Println("Error scaling down: ", err)
		return
	}

	r.nodes = r.nodes[:len(r.nodes)-1]
	log.Printf("Scaled down, node removed: %s, total nodes: %d\n", nodeToRemove, len(r.nodes))
}

// addNode adds a new node to the blockchain network
func (r *ResourceAllocator) addNode() (string, error) {
	// Implement the logic to add a node to your blockchain network
	// For AWS:
	ec2Svc := ec2.New(r.awsSession)
	runResult, err := ec2Svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String("ami-0abcdef1234567890"), // Example AMI ID
		InstanceType: aws.String("t2.micro"),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to start new instance")
	}

	newNodeID := *runResult.Instances[0].InstanceId
	return newNodeID, nil
}

// removeNode removes a node from the blockchain network
func (r *ResourceAllocator) removeNode(nodeID string) error {
	// Implement the logic to remove a node from your blockchain network
	// For AWS:
	ec2Svc := ec2.New(r.awsSession)
	_, err := ec2Svc.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(nodeID)},
	})
	if err != nil {
		return errors.Wrap(err, "failed to terminate instance")
	}
	return nil
}

// addGoogleNode adds a new node to the blockchain network in Google Cloud
func (r *ResourceAllocator) addGoogleNode() (string, error) {
	instance := &compute.Instance{
		Name:        "example-instance",
		MachineType: "zones/us-central1-a/machineTypes/f1-micro",
		Disks: []*compute.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: "projects/debian-cloud/global/images/family/debian-9",
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					{
						Type: "ONE_TO_ONE_NAT",
						Name: "External NAT",
					},
				},
			},
		},
	}

	op, err := r.googleClient.Instances.Insert("my-project", "us-central1-a", instance).Do()
	if err != nil {
		return "", errors.Wrap(err, "failed to start new Google Cloud instance")
	}

	return op.TargetId, nil
}

// removeGoogleNode removes a node from the blockchain network in Google Cloud
func (r *ResourceAllocator) removeGoogleNode(nodeID string) error {
	op, err := r.googleClient.Instances.Delete("my-project", "us-central1-a", nodeID).Do()
	if err != nil {
		return errors.Wrap(err, "failed to terminate Google Cloud instance")
	}
	return nil
}
