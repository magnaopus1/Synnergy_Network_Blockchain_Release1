package containerization

import (
	"context"
	"fmt"
	"log"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesManager handles Kubernetes operations
type KubernetesManager struct {
	Clientset *kubernetes.Clientset
}

// NewKubernetesManager initializes a new KubernetesManager
func NewKubernetesManager(kubeconfig string) (*KubernetesManager, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build kubeconfig: %v", err)
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
		return nil, err
	}

	return &KubernetesManager{Clientset: clientset}, nil
}

// CreateDeployment creates a Kubernetes deployment
func (km *KubernetesManager) CreateDeployment(namespace, deploymentName, image string, replicas int32, port int32) error {
	deploymentsClient := km.Clientset.AppsV1().Deployments(namespace)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": deploymentName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": deploymentName,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  deploymentName,
							Image: image,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: port,
								},
							},
						},
					},
				},
			},
		},
	}

	log.Printf("Creating deployment %s...", deploymentName)
	_, err := deploymentsClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment: %v", err)
	}
	log.Printf("Deployment %s created successfully.", deploymentName)
	return nil
}

// CreateService creates a Kubernetes service
func (km *KubernetesManager) CreateService(namespace, serviceName, deploymentName string, port int32) error {
	servicesClient := km.Clientset.CoreV1().Services(namespace)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": deploymentName,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
				},
			},
		},
	}

	log.Printf("Creating service %s...", serviceName)
	_, err := servicesClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	log.Printf("Service %s created successfully.", serviceName)
	return nil
}

// UpdateDeployment updates a Kubernetes deployment
func (km *KubernetesManager) UpdateDeployment(namespace, deploymentName, image string, replicas int32, port int32) error {
	deploymentsClient := km.Clientset.AppsV1().Deployments(namespace)

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get the latest version of Deployment before attempting update
		result, getErr := deploymentsClient.Get(context.TODO(), deploymentName, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("failed to get latest version of Deployment: %v", getErr)
		}

		result.Spec.Replicas = &replicas
		result.Spec.Template.Spec.Containers[0].Image = image
		result.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort = port

		_, updateErr := deploymentsClient.Update(context.TODO(), result, metav1.UpdateOptions{})
		return updateErr
	})
	if retryErr != nil {
		return fmt.Errorf("failed to update Deployment: %v", retryErr)
	}
	log.Printf("Deployment %s updated successfully.", deploymentName)
	return nil
}

// DeleteDeployment deletes a Kubernetes deployment
func (km *KubernetesManager) DeleteDeployment(namespace, deploymentName string) error {
	deploymentsClient := km.Clientset.AppsV1().Deployments(namespace)

	log.Printf("Deleting deployment %s...", deploymentName)
	deletePolicy := metav1.DeletePropagationForeground
	if err := deploymentsClient.Delete(context.TODO(), deploymentName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}); err != nil {
		return fmt.Errorf("failed to delete Deployment: %v", err)
	}
	log.Printf("Deployment %s deleted successfully.", deploymentName)
	return nil
}

// ListDeployments lists all deployments in a namespace
func (km *KubernetesManager) ListDeployments(namespace string) error {
	deploymentsClient := km.Clientset.AppsV1().Deployments(namespace)

	log.Printf("Listing deployments in namespace %s...", namespace)
	list, err := deploymentsClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list Deployments: %v", err)
	}

	for _, d := range list.Items {
		log.Printf(" * %s (%d replicas)\n", d.Name, *d.Spec.Replicas)
	}
	return nil
}

// GetDeploymentLogs retrieves logs from a Kubernetes deployment
func (km *KubernetesManager) GetDeploymentLogs(namespace, podName string) (string, error) {
	podsClient := km.Clientset.CoreV1().Pods(namespace)

	logOptions := &corev1.PodLogOptions{}
	req := podsClient.GetLogs(podName, logOptions)
	logStream, err := req.Stream(context.TODO())
	if err != nil {
		return "", fmt.Errorf("failed to get logs from pod %s: %v", podName, err)
	}
	defer logStream.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(logStream)
	logs := buf.String()

	log.Printf("Logs from pod %s: %s", podName, logs)
	return logs, nil
}

