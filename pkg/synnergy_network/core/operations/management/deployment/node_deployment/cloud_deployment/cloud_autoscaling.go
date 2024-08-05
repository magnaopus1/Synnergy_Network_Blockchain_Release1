package cloud_deployment

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/lambda"
)

// AWSAutoScalingSetup holds configuration for setting up AWS auto-scaling
type AWSAutoScalingSetup struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// NewAWSAutoScalingSetup initializes a new AWSAutoScalingSetup instance
func NewAWSAutoScalingSetup(region, accessKeyID, secretAccessKey, sessionToken string) *AWSAutoScalingSetup {
	return &AWSAutoScalingSetup{
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}
}

// createAWSSession creates a new AWS session
func (awsSetup *AWSAutoScalingSetup) createAWSSession() (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(awsSetup.Region),
		Credentials: credentials.NewStaticCredentials(awsSetup.AccessKeyID, awsSetup.SecretAccessKey, awsSetup.SessionToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}
	return sess, nil
}

// CreateAutoScalingGroup creates a new auto-scaling group
func (awsSetup *AWSAutoScalingSetup) CreateAutoScalingGroup(groupName, launchConfigurationName, loadBalancerName string, minSize, maxSize, desiredCapacity int64) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := autoscaling.New(sess)
	input := &autoscaling.CreateAutoScalingGroupInput{
		AutoScalingGroupName:    aws.String(groupName),
		LaunchConfigurationName: aws.String(launchConfigurationName),
		MinSize:                 aws.Int64(minSize),
		MaxSize:                 aws.Int64(maxSize),
		DesiredCapacity:         aws.Int64(desiredCapacity),
		AvailabilityZones:       []*string{aws.String(awsSetup.Region + "a"), aws.String(awsSetup.Region + "b")},
		LoadBalancerNames:       []*string{aws.String(loadBalancerName)},
	}

	_, err = svc.CreateAutoScalingGroup(input)
	if err != nil {
		return fmt.Errorf("failed to create auto-scaling group: %v", err)
	}

	fmt.Printf("Auto-scaling group %s created successfully\n", groupName)
	return nil
}

// CreateLaunchConfiguration creates a new launch configuration
func (awsSetup *AWSAutoScalingSetup) CreateLaunchConfiguration(configName, imageID, instanceType, keyName, securityGroup string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := autoscaling.New(sess)
	input := &autoscaling.CreateLaunchConfigurationInput{
		LaunchConfigurationName: aws.String(configName),
		ImageId:                 aws.String(imageID),
		InstanceType:            aws.String(instanceType),
		KeyName:                 aws.String(keyName),
		SecurityGroups:          []*string{aws.String(securityGroup)},
	}

	_, err = svc.CreateLaunchConfiguration(input)
	if err != nil {
		return fmt.Errorf("failed to create launch configuration: %v", err)
	}

	fmt.Printf("Launch configuration %s created successfully\n", configName)
	return nil
}

// CreateScalingPolicy creates a new scaling policy
func (awsSetup *AWSAutoScalingSetup) CreateScalingPolicy(policyName, groupName string, adjustmentType string, scalingAdjustment int64) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := autoscaling.New(sess)
	input := &autoscaling.PutScalingPolicyInput{
		AutoScalingGroupName: aws.String(groupName),
		PolicyName:           aws.String(policyName),
		AdjustmentType:       aws.String(adjustmentType),
		ScalingAdjustment:    aws.Int64(scalingAdjustment),
	}

	_, err = svc.PutScalingPolicy(input)
	if err != nil {
		return fmt.Errorf("failed to create scaling policy: %v", err)
	}

	fmt.Printf("Scaling policy %s created successfully\n", policyName)
	return nil
}

// AttachLoadBalancer attaches a load balancer to the auto-scaling group
func (awsSetup *AWSAutoScalingSetup) AttachLoadBalancer(groupName, loadBalancerName string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := autoscaling.New(sess)
	input := &autoscaling.AttachLoadBalancersInput{
		AutoScalingGroupName: aws.String(groupName),
		LoadBalancerNames:    []*string{aws.String(loadBalancerName)},
	}

	_, err = svc.AttachLoadBalancers(input)
	if err != nil {
		return fmt.Errorf("failed to attach load balancer: %v", err)
	}

	fmt.Printf("Load balancer %s attached to auto-scaling group %s\n", loadBalancerName, groupName)
	return nil
}

// CreateCloudWatchAlarm creates a new CloudWatch alarm
func (awsSetup *AWSAutoScalingSetup) CreateCloudWatchAlarm(alarmName, metricName, namespace, statistic, comparisonOperator string, threshold float64, period, evaluationPeriods int64, actionsEnabled bool, alarmActions []*string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := cloudwatch.New(sess)
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmName:          aws.String(alarmName),
		MetricName:         aws.String(metricName),
		Namespace:          aws.String(namespace),
		Statistic:          aws.String(statistic),
		ComparisonOperator: aws.String(comparisonOperator),
		Threshold:          aws.Float64(threshold),
		Period:             aws.Int64(period),
		EvaluationPeriods:  aws.Int64(evaluationPeriods),
		ActionsEnabled:     aws.Bool(actionsEnabled),
		AlarmActions:       alarmActions,
	}

	_, err = svc.PutMetricAlarm(input)
	if err != nil {
		return fmt.Errorf("failed to create CloudWatch alarm: %v", err)
	}

	fmt.Printf("CloudWatch alarm %s created successfully\n", alarmName)
	return nil
}

// CreateSNS creates a new SNS topic and subscription for alarm notifications
func (awsSetup *AWSAutoScalingSetup) CreateSNS(topicName, email string) (string, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return "", err
	}

	svc := sns.New(sess)
	topicOutput, err := svc.CreateTopic(&sns.CreateTopicInput{
		Name: aws.String(topicName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create SNS topic: %v", err)
	}

	subscribeInput := &sns.SubscribeInput{
		Endpoint:              aws.String(email),
		Protocol:              aws.String("email"),
		ReturnSubscriptionArn: aws.Bool(true),
		TopicArn:              topicOutput.TopicArn,
	}

	_, err = svc.Subscribe(subscribeInput)
	if err != nil {
		return "", fmt.Errorf("failed to subscribe to SNS topic: %v", err)
	}

	fmt.Printf("SNS topic %s created and email subscription added successfully\n", topicName)
	return *topicOutput.TopicArn, nil
}

// CreateLambdaFunction creates a new Lambda function
func (awsSetup *AWSAutoScalingSetup) CreateLambdaFunction(functionName, roleArn, handler, zipFilePath string) error {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return err
	}

	svc := lambda.New(sess)
	code := &lambda.FunctionCode{
		ZipFile: []byte(zipFilePath),
	}

	input := &lambda.CreateFunctionInput{
		Code:         code,
		FunctionName: aws.String(functionName),
		Handler:      aws.String(handler),
		Role:         aws.String(roleArn),
		Runtime:      aws.String("nodejs14.x"),
	}

	_, err = svc.CreateFunction(input)
	if err != nil {
		return fmt.Errorf("failed to create Lambda function: %v", err)
	}

	fmt.Printf("Lambda function %s created successfully\n", functionName)
	return nil
}

// CreateIAMRole creates a new IAM role
func (awsSetup *AWSAutoScalingSetup) CreateIAMRole(roleName, policyDocument string) (*iam.Role, error) {
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
func (awsSetup *AWSAutoScalingSetup) AttachRolePolicy(roleName, policyArn string) error {
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

// ListAutoScalingGroups lists all auto-scaling groups
func (awsSetup *AWSAutoScalingSetup) ListAutoScalingGroups() ([]*autoscaling.Group, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := autoscaling.New(sess)
	input := &autoscaling.DescribeAutoScalingGroupsInput{}

	result, err := svc.DescribeAutoScalingGroups(input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe auto-scaling groups: %v", err)
	}

	return result.AutoScalingGroups, nil
}

// ListEC2Instances lists all EC2 instances in the auto-scaling group
func (awsSetup *AWSAutoScalingSetup) ListEC2Instances(groupName string) ([]*ec2.Instance, error) {
	sess, err := awsSetup.createAWSSession()
	if err != nil {
		return nil, err
	}

	svc := ec2.New(sess)
	input := &autoscaling.DescribeAutoScalingInstancesInput{}
	autoScalingSvc := autoscaling.New(sess)
	autoScalingResult, err := autoScalingSvc.DescribeAutoScalingInstances(input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe auto-scaling instances: %v", err)
	}

	var instances []*ec2.Instance
	for _, instance := range autoScalingResult.AutoScalingInstances {
		if *instance.AutoScalingGroupName == groupName {
			ec2Input := &ec2.DescribeInstancesInput{
				InstanceIds: []*string{instance.InstanceId},
			}
			ec2Result, err := svc.DescribeInstances(ec2Input)
			if err != nil {
				return nil, fmt.Errorf("failed to describe EC2 instances: %v", err)
			}
			for _, reservation := range ec2Result.Reservations {
				instances = append(instances, reservation.Instances...)
			}
		}
	}

	return instances, nil
}
