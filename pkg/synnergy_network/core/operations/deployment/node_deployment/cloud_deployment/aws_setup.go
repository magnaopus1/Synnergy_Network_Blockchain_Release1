package cloud_deployment

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/pkg/errors"
)

// AWSConfig holds configuration details for AWS deployment.
type AWSConfig struct {
	Region          string
	InstanceType    string
	KeyName         string
	SecurityGroupID string
	ImageID         string
	TagKey          string
	TagValue        string
}

// NodeDeployment holds the necessary information for deploying a node.
type NodeDeployment struct {
	Config *AWSConfig
	EC2    *ec2.EC2
	SSM    *ssm.SSM
}

// NewSession creates a new AWS session.
func NewSession(region string) (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new AWS session")
	}
	return sess, nil
}

// NewNodeDeployment initializes a new NodeDeployment.
func NewNodeDeployment(config *AWSConfig) (*NodeDeployment, error) {
	sess, err := NewSession(config.Region)
	if err != nil {
		return nil, err
	}

	return &NodeDeployment{
		Config: config,
		EC2:    ec2.New(sess),
		SSM:    ssm.New(sess),
	}, nil
}

// CreateEC2Instance creates an EC2 instance for the node.
func (nd *NodeDeployment) CreateEC2Instance() (*ec2.Instance, error) {
	runResult, err := nd.EC2.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(nd.Config.ImageID),
		InstanceType: aws.String(nd.Config.InstanceType),
		KeyName:      aws.String(nd.Config.KeyName),
		SecurityGroupIds: []*string{
			aws.String(nd.Config.SecurityGroupID),
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String(nd.Config.TagKey),
						Value: aws.String(nd.Config.TagValue),
					},
				},
			},
		},
		MinCount: aws.Int64(1),
		MaxCount: aws.Int64(1),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create EC2 instance")
	}

	// Waiting for the instance to be in running state
	instanceID := runResult.Instances[0].InstanceId
	log.Printf("Waiting for instance %s to be in running state", *instanceID)

	err = nd.EC2.WaitUntilInstanceRunning(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to wait for instance to be running")
	}

	log.Printf("Instance %s is now running", *instanceID)

	// Fetching the instance details
	descResult, err := nd.EC2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to describe instance")
	}

	return descResult.Reservations[0].Instances[0], nil
}

// InstallNodeSoftware installs necessary software on the EC2 instance.
func (nd *NodeDeployment) InstallNodeSoftware(instanceID, script string) error {
	commandInput := &ssm.SendCommandInput{
		DocumentName: aws.String("AWS-RunShellScript"),
		InstanceIds:  []*string{aws.String(instanceID)},
		Parameters: map[string][]*string{
			"commands": {
				aws.String(script),
			},
		},
	}

	sendCmdResult, err := nd.SSM.SendCommand(commandInput)
	if err != nil {
		return errors.Wrap(err, "failed to send command")
	}

	commandID := sendCmdResult.Command.CommandId
	log.Printf("Waiting for command %s to complete on instance %s", *commandID, instanceID)

	err = nd.waitForCommandResult(instanceID, *commandID)
	if err != nil {
		return errors.Wrap(err, "failed to wait for command result")
	}

	log.Printf("Node software installed successfully on instance %s", instanceID)
	return nil
}

// waitForCommandResult waits for the command execution result.
func (nd *NodeDeployment) waitForCommandResult(instanceID, commandID string) error {
	for {
		output, err := nd.SSM.GetCommandInvocation(&ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			return errors.Wrap(err, "failed to get command invocation")
		}

		switch *output.Status {
		case ssm.CommandInvocationStatusSuccess:
			return nil
		case ssm.CommandInvocationStatusFailed:
			return errors.Errorf("command failed: %s", *output.StandardErrorContent)
		default:
			time.Sleep(5 * time.Second)
		}
	}
}

// DeployNode orchestrates the entire node deployment process.
func (nd *NodeDeployment) DeployNode(script string) error {
	instance, err := nd.CreateEC2Instance()
	if err != nil {
		return err
	}

	err = nd.InstallNodeSoftware(*instance.InstanceId, script)
	if err != nil {
		return err
	}

	log.Printf("Node deployed successfully with instance ID %s", *instance.InstanceId)
	return nil
}

