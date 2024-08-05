package cloud_deployment

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"
	"golang.org/x/crypto/scrypt"
)

// AWSConfig contains the necessary configuration for AWS setup
type AWSConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	S3BucketName    string
	EC2InstanceType string
	KeyPairName     string
}

// SetupAWS performs the setup of AWS services required for the blockchain network
func SetupAWS(config AWSConfig) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(config.Region),
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %v", err)
	}

	if err := setupS3Bucket(sess, config.S3BucketName); err != nil {
		return fmt.Errorf("failed to setup S3 bucket: %v", err)
	}

	if err := setupEC2Instance(sess, config); err != nil {
		return fmt.Errorf("failed to setup EC2 instance: %v", err)
	}

	if err := setupSSMParameters(sess, config); err != nil {
		return fmt.Errorf("failed to setup SSM parameters: %v", err)
	}

	return nil
}

// setupS3Bucket creates an S3 bucket if it doesn't already exist
func setupS3Bucket(sess *session.Session, bucketName string) error {
	svc := s3.New(sess)
	_, err := svc.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to create S3 bucket: %v", err)
	}

	err = svc.WaitUntilBucketExists(&s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to wait for bucket to exist: %v", err)
	}

	log.Printf("S3 bucket %s created successfully", bucketName)
	return nil
}

// setupEC2Instance launches an EC2 instance with the specified configuration
func setupEC2Instance(sess *session.Session, config AWSConfig) error {
	svc := ec2.New(sess)

	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String("ami-0c55b159cbfafe1f0"), // Example AMI ID, replace with your preferred AMI ID
		InstanceType: aws.String(config.EC2InstanceType),
		KeyName:      aws.String(config.KeyPairName),
		MinCount:     aws.Int64(1),
		MaxCount:     aws.Int64(1),
	})
	if err != nil {
		return fmt.Errorf("failed to launch EC2 instance: %v", err)
	}

	instanceID := runResult.Instances[0].InstanceId
	log.Printf("EC2 instance %s launched successfully", *instanceID)

	err = svc.WaitUntilInstanceRunning(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("failed to wait for instance to run: %v", err)
	}

	log.Printf("EC2 instance %s is running", *instanceID)
	return nil
}

// setupSSMParameters stores configuration parameters in AWS Systems Manager Parameter Store
func setupSSMParameters(sess *session.Session, config AWSConfig) error {
	ssmSvc := ssm.New(sess)

	parameters := map[string]string{
		"/synnergy_network/region":           config.Region,
		"/synnergy_network/access_key_id":    config.AccessKeyID,
		"/synnergy_network/secret_access_key": config.SecretAccessKey,
		"/synnergy_network/s3_bucket_name":   config.S3BucketName,
	}

	for key, value := range parameters {
		_, err := ssmSvc.PutParameter(&ssm.PutParameterInput{
			Name:  aws.String(key),
			Type:  aws.String("String"),
			Value: aws.String(value),
		})
		if err != nil {
			return fmt.Errorf("failed to put SSM parameter %s: %v", key, err)
		}
	}

	log.Println("SSM parameters set successfully")
	return nil
}

// Utility function for generating secure keys using scrypt
func generateSecureKey(password, salt []byte, keyLen int) ([]byte, error) {
	const N = 32768
	const r = 8
	const p = 1

	key, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure key: %v", err)
	}

	return key, nil
}

