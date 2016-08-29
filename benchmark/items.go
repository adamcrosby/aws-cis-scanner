package benchmark

// Section 1: Identity and access management
const (
	Finding1_1Txt = "Avoid the use of the 'root' account (Scored)"
	Finding1_2Txt = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)"
	Finding1_3Txt = "Ensure credentials unused for 90 days or greater are disabled (Scored)"
	Finding1_4Txt = "Ensure access keys are rotated every 90 days or less (Scored)"
	Finding1_5Txt = "Ensure IAM password policy requires at least one uppercase letter (Scored)"

	Finding1_6Txt = "Ensure IAM password policy require at least one lowercase letter (Scored)"

	Finding1_7Txt = "Ensure IAM password policy require at least one symbol (Scored)"

	Finding1_8Txt = "Ensure IAM password policy require at least one number (Scored)"

	Finding1_9Txt = "Ensure IAM password policy requires minimum length of 14 or greater (Scored)"
	//Finding1_9Val  = 14
	Finding1_10Txt = "Ensure IAM password policy prevents password reuse (Scored)"
	Finding1_11Txt = "Ensure IAM password policy expires passwords within 90 days or less (Scored)"
	//Finding1_11Val = 90
	Finding1_12Txt = "Ensure no root account access key exists (Scored)"
	Finding1_13Txt = "Ensure hardware MFA is enabled for the 'root' account (Scored)"
	Finding1_14Txt = "Ensure security questions are registered in the AWS account (Not Scored)"
	Finding1_15Txt = "Ensure IAM policies are attached only to groups or roles (Scored)"
)

// Section 2: Logging
const (
	Finding2_1Txt = "Ensure CloudTrail is enabled in all regions (Scored)"
	Finding2_2Txt = "Ensure CloudTrail log file validation is enabled (Scored)"
	Finding2_3Txt = "Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)"
	Finding2_4Txt = "Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)"
	Finding2_5Txt = "Ensure AWS Config is enabled in all regions (Scored)"
	Finding2_6Txt = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)"
	Finding2_7Txt = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)"
	Finding2_8Txt = "Ensure rotation for customer created CMKs is enabled (Scored)"
)

// Section 3: Monitoring
const (
	Finding3_1Txt  = "Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)"
	Finding3_2Txt  = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)"
	Finding3_3Txt  = "Ensure a log metric filter and alarm exist for usage of 'root' account (Scored)"
	Finding3_4Txt  = "Ensure a log metric filter and alarm exist for IAM policy changes (Scored)"
	Finding3_5Txt  = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
	Finding3_6Txt  = "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)"
	Finding3_7Txt  = "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)"
	Finding3_8Txt  = "Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)"
	Finding3_9Txt  = "Ensure a log metric filter and alarm exist for AWS Config configuration changes"
	Finding3_10Txt = "Ensure a log metric filter and alarm exist for security group changes (Scored)"
	Finding3_11Txt = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)"
	Finding3_12Txt = "Ensure a log metric filter and alarm exist for changes to network gateways"
	Finding3_13Txt = "Ensure a log metric filter and alarm exist for route table changes (Scored)"
	Finding3_14Txt = "Ensure a log metric filter and alarm exist for VPC changes (Scored)"
	Finding3_15Txt = "Ensure security contact information is registered (Scored)"
	Finding3_16Txt = "Ensure appropriate subscribers to each SNS topic (Not Scored)"
)

// Section 4: Networking
const (
	Finding4_1Txt = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)"
	Finding4_2Txt = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)"
	Finding4_3Txt = "Ensure VPC Flow Logging is Enabled in all Applicable Regions (Scored)"
	Finding4_4Txt = "Ensure the default security group restricts all traffic (Scored)"
)
