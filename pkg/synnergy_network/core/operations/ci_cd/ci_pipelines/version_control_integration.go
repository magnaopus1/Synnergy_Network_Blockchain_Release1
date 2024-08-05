package ci_pipelines

import (
    "log"
    "os/exec"
    "strings"
)

// VersionControlIntegration handles integration with version control systems like Git.
type VersionControlIntegration struct {
    RepoURL         string
    Branch          string
    CommitID        string
    BuildDirectory  string
    VersionControl  string // e.g., "git"
}

// NewVersionControlIntegration initializes a new VersionControlIntegration instance.
func NewVersionControlIntegration(repoURL, branch, buildDirectory, versionControl string) *VersionControlIntegration {
    return &VersionControlIntegration{
        RepoURL:        repoURL,
        Branch:         branch,
        BuildDirectory: buildDirectory,
        VersionControl: versionControl,
    }
}

// CloneRepository clones the repository to the build directory.
func (vci *VersionControlIntegration) CloneRepository() error {
    cmd := exec.Command(vci.VersionControl, "clone", "-b", vci.Branch, vci.RepoURL, vci.BuildDirectory)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to clone repository: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Repository cloned successfully. Output: %s\n", string(output))
    return nil
}

// FetchUpdates fetches the latest updates from the remote repository.
func (vci *VersionControlIntegration) FetchUpdates() error {
    cmd := exec.Command(vci.VersionControl, "fetch", "--all")
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to fetch updates: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Updates fetched successfully. Output: %s\n", string(output))
    return nil
}

// CheckoutBranch checks out the specified branch.
func (vci *VersionControlIntegration) CheckoutBranch(branch string) error {
    cmd := exec.Command(vci.VersionControl, "checkout", branch)
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to checkout branch: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Branch checked out successfully. Output: %s\n", string(output))
    return nil
}

// MergeBranch merges the specified branch into the current branch.
func (vci *VersionControlIntegration) MergeBranch(branch string) error {
    cmd := exec.Command(vci.VersionControl, "merge", branch)
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to merge branch: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Branch merged successfully. Output: %s\n", string(output))
    return nil
}

// GetLatestCommitID retrieves the latest commit ID from the current branch.
func (vci *VersionControlIntegration) GetLatestCommitID() (string, error) {
    cmd := exec.Command(vci.VersionControl, "rev-parse", "HEAD")
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to get latest commit ID: %s\nOutput: %s\n", err, string(output))
        return "", err
    }
    commitID := strings.TrimSpace(string(output))
    vci.CommitID = commitID
    log.Printf("Latest commit ID retrieved: %s\n", commitID)
    return commitID, nil
}

// CreateBranch creates a new branch from the current branch.
func (vci *VersionControlIntegration) CreateBranch(newBranch string) error {
    cmd := exec.Command(vci.VersionControl, "checkout", "-b", newBranch)
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to create new branch: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("New branch created successfully. Output: %s\n", string(output))
    return nil
}

// CommitChanges commits changes in the build directory with a provided message.
func (vci *VersionControlIntegration) CommitChanges(commitMessage string) error {
    cmd := exec.Command(vci.VersionControl, "commit", "-am", commitMessage)
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to commit changes: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Changes committed successfully. Output: %s\n", string(output))
    return nil
}

// PushChanges pushes the local changes to the remote repository.
func (vci *VersionControlIntegration) PushChanges() error {
    cmd := exec.Command(vci.VersionControl, "push")
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to push changes: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Changes pushed successfully. Output: %s\n", string(output))
    return nil
}

// TagCommit tags the latest commit with a given tag.
func (vci *VersionControlIntegration) TagCommit(tag string) error {
    cmd := exec.Command(vci.VersionControl, "tag", tag)
    cmd.Dir = vci.BuildDirectory
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to tag commit: %s\nOutput: %s\n", err, string(output))
        return err
    }
    log.Printf("Commit tagged successfully. Output: %s\n", string(output))
    return nil
}
