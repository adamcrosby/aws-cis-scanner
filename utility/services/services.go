package services

import (
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
)

// AWSServices provides pointers to the various services used in the checks, and is easier than pushing around dozens of individual arguments.
type AWSServices struct {
	IAM            *iam.IAM
	CloudTrail     *cloudtrail.CloudTrail
	S3Primary      *s3.S3
	S3Alt          *s3.S3
	Config         *configservice.ConfigService
	KMS            *kms.KMS
	CloudWatch     *cloudwatch.CloudWatch
	CloudWatchLogs *cloudwatchlogs.CloudWatchLogs
	SNS            *sns.SNS
	EC2            *ec2.EC2
}
