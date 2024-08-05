package deployment

import (
	"fmt"
	"log"
	"os/exec"
	"time"
)

// DeploymentScript represents the structure for deployment scripts
type DeploymentScript struct {
	Name       string
	Path       string
	Parameters map[string]string
	ExecutedAt time.Time
	Status     string
}

// NewDeploymentScript creates a new deployment script instance
func NewDeploymentScript(name, path string, parameters map[string]string) *DeploymentScript {
	return &DeploymentScript{
		Name:       name,
		Path:       path,
		Parameters: parameters,
		Status:     "pending",
	}
}

// Execute runs the deployment script with the given parameters
func (ds *DeploymentScript) Execute() error {
	ds.ExecutedAt = time.Now()
	args := []string{}
	for key, value := range ds.Parameters {
		args = append(args, fmt.Sprintf("--%s=%s", key, value))
	}
	cmd := exec.Command(ds.Path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		ds.Status = "failed"
		log.Printf("Failed to execute script %s: %s\n", ds.Name, string(output))
		return err
	}
	ds.Status = "success"
	log.Printf("Successfully executed script %s: %s\n", ds.Name, string(output))
	return nil
}

// ListScripts lists all available deployment scripts in the given directory
func ListScripts(directory string) ([]DeploymentScript, error) {
	// This function would ideally scan the directory for scripts and return them
	// For now, let's return an example list
	scripts := []DeploymentScript{
		{Name: "Setup Network", Path: directory + "/setup_network.sh"},
		{Name: "Deploy Nodes", Path: directory + "/deploy_nodes.sh"},
	}
	return scripts, nil
}

// ScheduleScript schedules a deployment script to run at a specified time
func (ds *DeploymentScript) ScheduleScript(executionTime time.Time) {
	duration := time.Until(executionTime)
	time.AfterFunc(duration, func() {
		err := ds.Execute()
		if err != nil {
			log.Printf("Scheduled execution of script %s failed: %s", ds.Name, err)
		}
	})
}

// ValidateParameters checks if the required parameters are present and valid
func (ds *DeploymentScript) ValidateParameters(requiredParams []string) error {
	for _, param := range requiredParams {
		if _, exists := ds.Parameters[param]; !exists {
			return fmt.Errorf("missing required parameter: %s", param)
		}
	}
	return nil
}

// CreateDeploymentReport generates a detailed report of the deployment execution
func (ds *DeploymentScript) CreateDeploymentReport() string {
	return fmt.Sprintf("Script Name: %s\nExecuted At: %s\nStatus: %s\n",
		ds.Name, ds.ExecutedAt.Format(time.RFC3339), ds.Status)
}
