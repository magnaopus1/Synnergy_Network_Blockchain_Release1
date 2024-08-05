package environment_provisioning

import (
	"log"
	"os/exec"
	"strings"
)

// AutomatedEnvironments handles the provisioning of environments using Infrastructure as Code (IaC) tools.
type AutomatedEnvironments struct {
	environmentName string
	tools           []string
}

// NewAutomatedEnvironments creates a new AutomatedEnvironments instance.
func NewAutomatedEnvironments(envName string, tools []string) *AutomatedEnvironments {
	return &AutomatedEnvironments{
		environmentName: envName,
		tools:           tools,
	}
}

// ProvisionEnvironment provisions the environment using the specified IaC tools.
func (ae *AutomatedEnvironments) ProvisionEnvironment() error {
	log.Printf("Starting provisioning for environment: %s\n", ae.environmentName)
	for _, tool := range ae.tools {
		if err := ae.runProvisioningTool(tool); err != nil {
			return err
		}
	}
	log.Printf("Provisioning completed for environment: %s\n", ae.environmentName)
	return nil
}

// runProvisioningTool executes the provisioning command for a given tool.
func (ae *AutomatedEnvironments) runProvisioningTool(tool string) error {
	log.Printf("Running provisioning tool: %s\n", tool)
	cmd := exec.Command(tool, "apply")
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running %s: %v\nOutput: %s\n", tool, err, string(cmdOutput))
		return err
	}
	log.Printf("Output from %s: %s\n", tool, string(cmdOutput))
	return nil
}

// DestroyEnvironment destroys the provisioned environment using the specified IaC tools.
func (ae *AutomatedEnvironments) DestroyEnvironment() error {
	log.Printf("Starting destruction for environment: %s\n", ae.environmentName)
	for _, tool := range ae.tools {
		if err := ae.runDestructionTool(tool); err != nil {
			return err
		}
	}
	log.Printf("Destruction completed for environment: %s\n", ae.environmentName)
	return nil
}

// runDestructionTool executes the destruction command for a given tool.
func (ae *AutomatedEnvironments) runDestructionTool(tool string) error {
	log.Printf("Running destruction tool: %s\n", tool)
	cmd := exec.Command(tool, "destroy")
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running %s: %v\nOutput: %s\n", tool, err, string(cmdOutput))
		return err
	}
	log.Printf("Output from %s: %s\n", tool, string(cmdOutput))
	return nil
}

// ListEnvironments lists all provisioned environments using the specified IaC tools.
func (ae *AutomatedEnvironments) ListEnvironments() ([]string, error) {
	var environments []string
	for _, tool := range ae.tools {
		envs, err := ae.listEnvironmentsWithTool(tool)
		if err != nil {
			return nil, err
		}
		environments = append(environments, envs...)
	}
	return environments, nil
}

// listEnvironmentsWithTool lists environments using a specific IaC tool.
func (ae *AutomatedEnvironments) listEnvironmentsWithTool(tool string) ([]string, error) {
	log.Printf("Listing environments with tool: %s\n", tool)
	cmd := exec.Command(tool, "list")
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running %s: %v\nOutput: %s\n", tool, err, string(cmdOutput))
		return nil, err
	}
	envs := strings.Split(string(cmdOutput), "\n")
	log.Printf("Environments listed with %s: %v\n", tool, envs)
	return envs, nil
}
