package containerization

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

const (
	kubeconfigEnvVar = "KUBECONFIG"
	namespace        = "synnergy-network"
)

// KubernetesManager manages Kubernetes deployments for Synnergy Network.
type KubernetesManager struct {
	clientset *v1.CoreV1Client
	config    *rest.Config
}

// NewKubernetesManager creates a new instance of KubernetesManager.
func NewKubernetesManager() (*KubernetesManager, error) {
	kubeconfig := os.Getenv(kubeconfigEnvVar)
	if kubeconfig == "" {
		kubeconfig = util.DefaultKubeletKubeConfigPath
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build Kubernetes config")
	}
	clientset, err := v1.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Kubernetes clientset")
	}
	return &KubernetesManager{
		clientset: clientset,
		config:    config,
	}, nil
}

// DeployNode deploys a Synnergy Network node on Kubernetes.
func (km *KubernetesManager) DeployNode(nodeName, image string) error {
	// Define the deployment configuration
	deployment := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeName,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "synnergy-node",
					Image: image,
					Ports: []v1.ContainerPort{
						{ContainerPort: 30303, Name: "p2p"},
						{ContainerPort: 8545, Name: "rpc"},
					},
					Resources: v1.ResourceRequirements{
						Requests: v1.ResourceList{
							"cpu":    "500m",
							"memory": "1Gi",
						},
						Limits: v1.ResourceList{
							"cpu":    "1000m",
							"memory": "2Gi",
						},
					},
				},
			},
		},
	}

	// Create the deployment
	_, err := km.clientset.Pods(namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to create node deployment")
	}
	return nil
}

// ScaleDeployment scales the Synnergy Network node deployment.
func (km *KubernetesManager) ScaleDeployment(nodeName string, replicas int32) error {
	scale := &v1.Scale{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeName,
			Namespace: namespace,
		},
		Spec: v1.ScaleSpec{
			Replicas: replicas,
		},
	}

	_, err := km.clientset.Pods(namespace).UpdateScale(context.TODO(), nodeName, scale, metav1.UpdateOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to scale deployment")
	}
	return nil
}

// UpdateNodeImage updates the Docker image of a Synnergy Network node.
func (km *KubernetesManager) UpdateNodeImage(nodeName, newImage string) error {
	// Get the current deployment
	deployment, err := km.clientset.Pods(namespace).Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to get node deployment")
	}

	// Update the image
	deployment.Spec.Containers[0].Image = newImage

	_, err = km.clientset.Pods(namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to update node image")
	}
	return nil
}

// DeleteNode deletes a Synnergy Network node deployment.
func (km *KubernetesManager) DeleteNode(nodeName string) error {
	err := km.clientset.Pods(namespace).Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to delete node deployment")
	}
	return nil
}

// ListNodes lists all Synnergy Network nodes in the Kubernetes cluster.
func (km *KubernetesManager) ListNodes() ([]string, error) {
	pods, err := km.clientset.Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}
	var nodeNames []string
	for _, pod := range pods.Items {
		nodeNames = append(nodeNames, pod.Name)
	}
	return nodeNames, nil
}

// GetNodeLogs retrieves the logs for a specific Synnergy Network node.
func (km *KubernetesManager) GetNodeLogs(nodeName string) (string, error) {
	req := km.clientset.Pods(namespace).GetLogs(nodeName, &v1.PodLogOptions{})
	logs, err := req.Stream(context.TODO())
	if err != nil {
		return "", errors.Wrap(err, "failed to get node logs")
	}
	defer logs.Close()

	var sb strings.Builder
	buf := make([]byte, 2000)
	for {
		numBytes, err := logs.Read(buf)
		if numBytes == 0 {
			break
		}
		if err != nil {
			return "", errors.Wrap(err, "error reading log stream")
		}
		sb.Write(buf[:numBytes])
	}
	return sb.String(), nil
}

// HealthCheck performs a health check on the Kubernetes cluster.
func (km *KubernetesManager) HealthCheck() error {
	nodes, err := km.clientset.Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to list nodes for health check")
	}
	for _, node := range nodes.Items {
		for _, condition := range node.Status.Conditions {
			if condition.Type == v1.NodeReady && condition.Status != v1.ConditionTrue {
				return fmt.Errorf("node %s is not ready", node.Name)
			}
		}
	}
	return nil
}

// DeployHelmChart deploys a Helm chart for Synnergy Network.
func (km *KubernetesManager) DeployHelmChart(chartPath, releaseName, namespace string, values map[string]string) error {
	args := []string{"install", releaseName, chartPath, "--namespace", namespace}
	for key, value := range values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.Command("helm", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to deploy Helm chart: %s", output)
	}
	log.Printf("Helm chart deployed: %s", output)
	return nil
}

// UpgradeHelmChart upgrades an existing Helm chart for Synnergy Network.
func (km *KubernetesManager) UpgradeHelmChart(chartPath, releaseName, namespace string, values map[string]string) error {
	args := []string{"upgrade", releaseName, chartPath, "--namespace", namespace}
	for key, value := range values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.Command("helm", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to upgrade Helm chart: %s", output)
	}
	log.Printf("Helm chart upgraded: %s", output)
	return nil
}

// RollbackHelmRelease rolls back a Helm release to a previous version.
func (km *KubernetesManager) RollbackHelmRelease(releaseName string, revision int) error {
	cmd := exec.Command("helm", "rollback", releaseName, fmt.Sprintf("%d", revision))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to rollback Helm release: %s", output)
	}
	log.Printf("Helm release rolled back: %s", output)
	return nil
}

// DeleteHelmRelease deletes a Helm release.
func (km *KubernetesManager) DeleteHelmRelease(releaseName string) error {
	cmd := exec.Command("helm", "uninstall", releaseName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to delete Helm release: %s", output)
	}
	log.Printf("Helm release deleted: %s", output)
	return nil
}

// ScheduleMaintenance schedules maintenance for Synnergy Network nodes.
func (km *KubernetesManager) ScheduleMaintenance(nodeName string, duration time.Duration) error {
	// Implementation of maintenance scheduling
	log.Printf("Scheduled maintenance for node %s for duration %v", nodeName, duration)
	return nil
}
