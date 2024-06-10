package scaling

import (
    "context"
    "log"
    "sync"
    "time"
    "cloud.google.com/go/compute/metadata"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/autoscaling"
    "github.com/aws/aws-sdk-go/service/ec2"
    "github.com/pkg/errors"
)

// AutoScaler manages automatic scaling of blockchain nodes
type AutoScaler struct {
    minNodes       int
    maxNodes       int
    cpuThreshold   float64
    memThreshold   float64
    scalingInterval time.Duration
    awsSession     *session.Session
    googleClient   *metadata.Client
    nodes          []string
    mutex          sync.Mutex
}

// NewAutoScaler initializes a new AutoScaler instance
func NewAutoScaler(minNodes, maxNodes int, cpuThreshold, memThreshold float64, scalingInterval time.Duration) (*AutoScaler, error) {
    awsSess, err := session.NewSession(&aws.Config{
        Region: aws.String("us-west-2")},
    )
    if err != nil {
        return nil, errors.Wrap(err, "failed to create AWS session")
    }

    googleClient, err := metadata.NewClient(nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create Google metadata client")
    }

    return &AutoScaler{
        minNodes:       minNodes,
        maxNodes:       maxNodes,
        cpuThreshold:   cpuThreshold,
        memThreshold:   memThreshold,
        scalingInterval: scalingInterval,
        awsSession:     awsSess,
        googleClient:   googleClient,
    }, nil
}

// MonitorAndScale monitors the network and scales nodes based on predefined thresholds
func (a *AutoScaler) MonitorAndScale(ctx context.Context) {
    ticker := time.NewTicker(a.scalingInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            a.scaleNodes()
        }
    }
}

// scaleNodes adjusts the number of active nodes based on CPU and memory usage
func (a *AutoScaler) scaleNodes() {
    cpuUsage, memUsage, err := a.collectMetrics()
    if err != nil {
        log.Println("Error collecting metrics: ", err)
        return
    }

    if cpuUsage > a.cpuThreshold || memUsage > a.memThreshold {
        a.scaleUp()
    } else {
        a.scaleDown()
    }
}

// collectMetrics collects CPU and memory usage metrics from nodes
func (a *AutoScaler) collectMetrics() (float64, float64, error) {
    a.mutex.Lock()
    defer a.mutex.Unlock()

    var totalCPUUsage, totalMemUsage float64
    var nodeCount int

    // Simulate metric collection from nodes
    for _, node := range a.nodes {
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
func (a *AutoScaler) scaleUp() {
    a.mutex.Lock()
    defer a.mutex.Unlock()

    if len(a.nodes) >= a.maxNodes {
        log.Println("Max nodes reached, cannot scale up further")
        return
    }

    newNode, err := a.addNode()
    if err != nil {
        log.Println("Error scaling up: ", err)
        return
    }

    a.nodes = append(a.nodes, newNode)
    log.Printf("Scaled up, new node added: %s, total nodes: %d\n", newNode, len(a.nodes))
}

// scaleDown decreases the number of active nodes
func (a *AutoScaler) scaleDown() {
    a.mutex.Lock()
    defer a.mutex.Unlock()

    if len(a.nodes) <= a.minNodes {
        log.Println("Min nodes reached, cannot scale down further")
        return
    }

    nodeToRemove := a.nodes[len(a.nodes)-1]
    if err := a.removeNode(nodeToRemove); err != nil {
        log.Println("Error scaling down: ", err)
        return
    }

    a.nodes = a.nodes[:len(a.nodes)-1]
    log.Printf("Scaled down, node removed: %s, total nodes: %d\n", nodeToRemove, len(a.nodes))
}

// addNode adds a new node to the blockchain network
func (a *AutoScaler) addNode() (string, error) {
    // Implement the logic to add a node to your blockchain network
    // For AWS:
    ec2Svc := ec2.New(a.awsSession)
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
func (a *AutoScaler) removeNode(nodeID string) error {
    // Implement the logic to remove a node from your blockchain network
    // For AWS:
    ec2Svc := ec2.New(a.awsSession)
    _, err := ec2Svc.TerminateInstances(&ec2.TerminateInstancesInput{
        InstanceIds: []*string{aws.String(nodeID)},
    })
    if err != nil {
        return errors.Wrap(err, "failed to terminate instance")
    }
    return nil
}
