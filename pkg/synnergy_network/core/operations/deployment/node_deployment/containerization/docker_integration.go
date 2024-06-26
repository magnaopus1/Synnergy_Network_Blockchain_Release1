package containerization

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/go-connections/nat"
)

// DockerManager handles Docker container operations
type DockerManager struct {
	Context context.Context
	Client  *client.Client
}

// NewDockerManager initializes a new DockerManager
func NewDockerManager(ctx context.Context) (*DockerManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}
	return &DockerManager{Context: ctx, Client: cli}, nil
}

// BuildImage builds a Docker image from the specified Dockerfile
func (dm *DockerManager) BuildImage(dockerfilePath, imageName string) error {
	dockerfile, err := exec.Command("cat", dockerfilePath).Output()
	if err != nil {
		return fmt.Errorf("failed to read Dockerfile: %v", err)
	}

	buildContext, err := archive.TarWithOptions(".", &archive.TarOptions{})
	if err != nil {
		return fmt.Errorf("failed to create build context: %v", err)
	}

	buildOptions := types.ImageBuildOptions{
		Context:    buildContext,
		Dockerfile: "Dockerfile",
		Tags:       []string{imageName},
		Remove:     true,
	}

	response, err := dm.Client.ImageBuild(dm.Context, buildContext, buildOptions)
	if err != nil {
		return fmt.Errorf("failed to build Docker image: %v", err)
	}
	defer response.Body.Close()

	err = jsonmessage.DisplayJSONMessagesStream(response.Body, bytes.NewBufferString(""), 0, false, nil)
	if err != nil {
		return fmt.Errorf("failed to display build output: %v", err)
	}

	log.Printf("Docker image %s built successfully", imageName)
	return nil
}

// RunContainer runs a Docker container from the specified image
func (dm *DockerManager) RunContainer(imageName, containerName string, portBindings map[string]string) (string, error) {
	portSet := nat.PortSet{}
	portMap := nat.PortMap{}

	for containerPort, hostPort := range portBindings {
		port := nat.Port(containerPort)
		portSet[port] = struct{}{}
		portMap[port] = []nat.PortBinding{{HostPort: hostPort}}
	}

	config := &container.Config{
		Image:        imageName,
		ExposedPorts: portSet,
	}
	hostConfig := &container.HostConfig{
		PortBindings: portMap,
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
	}

	resp, err := dm.Client.ContainerCreate(dm.Context, config, hostConfig, nil, nil, containerName)
	if err != nil {
		return "", fmt.Errorf("failed to create Docker container: %v", err)
	}

	if err := dm.Client.ContainerStart(dm.Context, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start Docker container: %v", err)
	}

	log.Printf("Docker container %s started successfully with ID %s", containerName, resp.ID)
	return resp.ID, nil
}

// StopContainer stops a running Docker container
func (dm *DockerManager) StopContainer(containerID string) error {
	timeout := 10 * time.Second
	err := dm.Client.ContainerStop(dm.Context, containerID, &timeout)
	if err != nil {
		return fmt.Errorf("failed to stop Docker container: %v", err)
	}

	log.Printf("Docker container %s stopped successfully", containerID)
	return nil
}

// RemoveContainer removes a Docker container
func (dm *DockerManager) RemoveContainer(containerID string) error {
	err := dm.Client.ContainerRemove(dm.Context, containerID, types.ContainerRemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("failed to remove Docker container: %v", err)
	}

	log.Printf("Docker container %s removed successfully", containerID)
	return nil
}

// ListContainers lists all running Docker containers
func (dm *DockerManager) ListContainers() ([]types.Container, error) {
	containers, err := dm.Client.ContainerList(dm.Context, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker containers: %v", err)
	}

	for _, container := range containers {
		log.Printf("Container ID: %s, Image: %s, Status: %s", container.ID, container.Image, container.Status)
	}

	return containers, nil
}

// GetContainerLogs retrieves logs from a Docker container
func (dm *DockerManager) GetContainerLogs(containerID string) (string, error) {
	options := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
	out, err := dm.Client.ContainerLogs(dm.Context, containerID, options)
	if err != nil {
		return "", fmt.Errorf("failed to get logs from Docker container: %v", err)
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(out)
	logs := buf.String()

	log.Printf("Logs from container %s: %s", containerID, logs)
	return logs, nil
}

// Main function for demonstration
func main() {
	ctx := context.Background()
	dockerManager, err := NewDockerManager(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize Docker manager: %v", err)
	}

	imageName := "synthron-node"
	containerName := "synthron-node-1"
	dockerfilePath := "./Dockerfile"

	err = dockerManager.BuildImage(dockerfilePath, imageName)
	if err != nil {
		log.Fatalf("Failed to build Docker image: %v", err)
	}

	portBindings := map[string]string{
		"8080/tcp": "8080",
	}

	containerID, err := dockerManager.RunContainer(imageName, containerName, portBindings)
	if err != nil {
		log.Fatalf("Failed to run Docker container: %v", err)
	}

	time.Sleep(30 * time.Second)

	err = dockerManager.GetContainerLogs(containerID)
	if err != nil {
		log.Fatalf("Failed to get container logs: %v", err)
	}

	err = dockerManager.StopContainer(containerID)
	if err != nil {
		log.Fatalf("Failed to stop Docker container: %v", err)
	}

	err = dockerManager.RemoveContainer(containerID)
	if err != nil {
		log.Fatalf("Failed to remove Docker container: %v", err)
	}

	containers, err := dockerManager.ListContainers()
	if err != nil {
		log.Fatalf("Failed to list Docker containers: %v", err)
	}
	for _, container := range containers {
		log.Printf("Running container ID: %s", container.ID)
	}
}
