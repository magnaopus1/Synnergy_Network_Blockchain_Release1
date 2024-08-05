package cloud_deployment

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
)

// AWSSetup struct holds the configuration for setting up AWS services
type AWSSetup struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// NewAWSSetup initializes a new AWSSetup instance
func NewAWSSetup(region, accessKeyID, secretAccessKey, sessionToken string) *AWSSetup {
	return &AWSSetup{
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}
}

// createAWSSession creates a new AWS session
func (awsSetup *AWSSetup) createAWSSession() (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(awsSetup.Region),
		Credentials: credentials.NewStaticCredentials(awsSetup.AccessKeyID, awsSetup.SecretAccessKey, awsSetup.SessionToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}
	return sess, nil
}

// CreateS3Bucket creates a new S3 bucket
func (awsSetup *AWSSetup) CreateS3Bucket(bucketName string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := s3.New(sess)
	_, err = svc.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to create S3 bucket: %v", err)
	}

	err = svc.WaitUntilBucketExists(&s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to wait for bucket to be created: %v", err)
	}

	fmt.Printf("Bucket %s created successfully\n", bucketName)
	return nil
}

// CreateEC2Instance creates a new EC2 instance
func (awsSetup *AWSSetup) CreateEC2Instance(instanceType, keyName, securityGroup, amiID string) (*ec2.Instance, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := ec2.New(sess)
	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(amiID),
		InstanceType: aws.String(instanceType),
		KeyName:      aws.String(keyName),
		SecurityGroupIds: []*string{
			aws.String(securityGroup),
		},
		MinCount: aws.Int64(1),
		MaxCount: aws.Int64(1),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create EC2 instance: %v", err)
	}

	fmt.Printf("Created instance %s\n", *runResult.Instances[0].InstanceId)
	return runResult.Instances[0], nil
}

// CreateEKSCluster creates a new EKS cluster
func (awsSetup *AWSSetup) CreateEKSCluster(clusterName, roleArn, vpcConfig string) (*eks.Cluster, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := eks.New(sess)
	input := &eks.CreateClusterInput{
		Name:    aws.String(clusterName),
		RoleArn: aws.String(roleArn),
		ResourcesVpcConfig: &eks.VpcConfigRequest{
			SubnetIds: aws.StringSlice(strings.Split(vpcConfig, ",")),
		},
	}

	result, err := svc.CreateCluster(input)
	if err != nil {
		return nil, fmt.Errorf("failed to create EKS cluster: %v", err)
	}

	fmt.Printf("Created EKS cluster %s\n", *result.Cluster.Name)
	return result.Cluster, nil
}

// CreateIAMRole creates a new IAM role
func (awsSetup *AWSSetup) CreateIAMRole(roleName, policyDocument string) (*iam.Role, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := iam.New(sess)
	input := &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(policyDocument),
	}

	result, err := svc.CreateRole(input)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM role: %v", err)
	}

	fmt.Printf("Created IAM role %s\n", *result.Role.RoleName)
	return result.Role, nil
}

// AttachRolePolicy attaches a policy to an IAM role
func (awsSetup *AWSSetup) AttachRolePolicy(roleName, policyArn string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := iam.New(sess)
	input := &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String(policyArn),
	}

	_, err = svc.AttachRolePolicy(input)
	if err != nil {
		return fmt.Errorf("failed to attach policy to role: %v", err)
	}

	fmt.Printf("Attached policy %s to role %s\n", policyArn, roleName)
	return nil
}

// CreateSSMParameter creates a new SSM parameter
func (awsSetup *AWSSetup) CreateSSMParameter(name, value, parameterType string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := ssm.New(sess)
	input := &ssm.PutParameterInput{
		Name:  aws.String(name),
		Value: aws.String(value),
		Type:  aws.String(parameterType),
	}

	_, err = svc.PutParameter(input)
	if err != nil {
		return fmt.Errorf("failed to create SSM parameter: %v", err)
	}

	fmt.Printf("Created SSM parameter %s\n", name)
	return nil
}

// GetCallerIdentity retrieves AWS account information
func (awsSetup *AWSSetup) GetCallerIdentity() (*sts.GetCallerIdentityOutput, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := sts.New(sess)
	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %v", err)
	}

	return result, nil
}

// ListEC2Instances lists all EC2 instances
func (awsSetup *AWSSetup) ListEC2Instances() ([]*ec2.Instance, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := ec2.New(sess)
	input := &ec2.DescribeInstancesInput{}

	result, err := svc.DescribeInstances(input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %v", err)
	}

	var instances []*ec2.Instance
	for _, reservation := range result.Reservations {
		instances = append(instances, reservation.Instances...)
	}

	return instances, nil
}
