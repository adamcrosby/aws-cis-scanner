package benchmark

import (
	"encoding/json"
	"fmt"

	"github.com/adamcrosby/aws-cis-scanner/utility/findings"
	"github.com/adamcrosby/aws-cis-scanner/utility/services"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

// AuthenticedUsersURI is the AWS Bucket Policy URI for all Authenticated users
const AuthenticedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

// AllUsersURI is the AWS Bucket Policy URI for all users
const AllUsersURI = "http://acs.amazonaws.com/groups/global/AllUsers"

/*
S3ACL for JSON decoding of S3 ACLs */
type S3ACL struct {
	Version   string
	Statement []S3ACLentry
}

/*
S3ACLentry for JSON decoding of S3 ACLs */
type S3ACLentry struct {
	Effect string
	//Principal S3ACLPrincipal
	Principal string
}

/*
LoggingChecks checks if cloudtrails are configured properly on this region
*/
func LoggingChecks(services services.AWSServices, checks findings.Checks) findings.Checks {
	//func LoggingChecks(kmsSvc *kms.KMS, configSvc *configservice.ConfigService, s3Svc *s3.S3, ct *cloudtrail.CloudTrail, checks findings.Checks, alts3Svc *s3.S3) findings.Checks {

	params := &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(true),
		TrailNameList:       []*string{},
	}
	trails, err := services.CloudTrail.DescribeTrails(params)

	if err != nil {
		panic(err)
	}
	checks["Finding 2.1"] = multiRegionEnabled(trails.TrailList)
	checks["Finding 2.2"] = logValidationEnabled(trails.TrailList)
	if services.S3Alt != nil {
		checks["Finding 2.3"] = ensureS3LogsBucketNotPublic(trails.TrailList, services.S3Alt)
	} else {
		checks["Finding 2.3"] = ensureS3LogsBucketNotPublic(trails.TrailList, services.S3Primary)
	}

	checks["Finding 2.4"] = cloudWatchIntegration(trails.TrailList, services.CloudTrail)
	checks["Finding 2.5"] = ensureConfigEnabled(services.Config)
	checks["Finding 2.6"] = ensureBucketLoggingEnabled(trails.TrailList, services.S3Primary)
	checks["Finding 2.7"] = ensureLogsEncrypted(trails.TrailList)
	checks["Finding 2.8"] = ensureCMKRotationEnabled(services.KMS)

	return checks
}

func multiRegionEnabled(trails []*cloudtrail.Trail) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.1", Description: Finding2_1Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}
	for i := range trails {
		if *trails[i].IsMultiRegionTrail {
			resp.Status.Open = findings.FindingClosed
		} else {
			resp.Notes["User"] = "No cloud trail is multi-region"
		}
	}
	return resp
}

func logValidationEnabled(trails []*cloudtrail.Trail) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.2", Description: Finding2_2Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}
	for i := range trails {
		if *trails[i].LogFileValidationEnabled {
			resp.Status.Open = findings.FindingClosed
		} else {
			// have to reset if ANY trail is false the check fails
			resp.Status.Open = findings.FindingOpen
			resp.Notes["User"] = fmt.Sprintf("%s does not have Log file validation enabled.", *trails[i].Name)
		}
	}
	return resp
}

func cloudWatchIntegration(trails []*cloudtrail.Trail, ct *cloudtrail.CloudTrail) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.4", Description: Finding2_4Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}

	var trailARN *string
	for i := range trails {
		// CloudWatchLogsLogGroupArn may be nil, so reference the pointer here instead
		// of dereferencing to the value
		if trails[i].CloudWatchLogsLogGroupArn != nil {
			// CloudWatchLogsLogGroupArn isn't nil, so it exists, so dereference here
			trailARN = trails[i].TrailARN
		}
	}
	// at least one of the CloudWatchLogsLogGroupArn settings was configured, so now
	// we need to check that Trail to make sure events have been delivered in the last day
	// or else fail the check
	if trailARN != nil {
		params := &cloudtrail.GetTrailStatusInput{Name: trailARN}
		trailstatus, err := ct.GetTrailStatus(params)
		if err != nil {
			panic(err)
		}
		// Ensure LatestCloudWatchLogsDeliveryTime is less than 1 day ago to pass checek
		if isActiveInLastDay(trailstatus.LatestCloudWatchLogsDeliveryTime) {
			resp.Status.Open = findings.FindingClosed
		} else {
			resp.Status.Open = findings.FindingOpen
			resp.Notes["User"] = fmt.Sprintf("%s does not have a delivery time in the last day", *trailARN)
		}

	}
	return resp
}

/*
* Finding 2.7 - Ensures log files are encrypted with KMS in cloud trail
 */
func ensureLogsEncrypted(trails []*cloudtrail.Trail) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.7", Description: Finding2_7Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}
	for i := range trails {
		if trails[i].KmsKeyId != nil {
			// Ensure struct member is present
			if *trails[i].KmsKeyId != "" {
				resp.Status.Open = findings.FindingClosed
			}
		} else {
			// have to reset if ANY trail is false the check fails
			resp.Status.Open = findings.FindingOpen
		}
	}
	return resp
}

func ensureS3LogsBucketNotPublic(trails []*cloudtrail.Trail, s3Svc *s3.S3) findings.Finding {
	// Default to finding Closed, only override if we find permissions: absence of perms == pass (default ACL is deny)
	resp := findings.Finding{Name: "Finding 2.3", Description: Finding2_3Txt, Status: findings.Status{Checked: true, Open: findings.FindingClosed}}

	acls := true
	for i := range trails {
		if trails[i].S3BucketName != nil {
			/* S3 Bucket ACL checks
			 */
			acls = s3BucketACLChecks(s3Svc, *trails[i].S3BucketName)
			/* S3 Buck Policy Checks
			 */
			acls = s3BucketPolicyChecks(s3Svc, *trails[i].S3BucketName)
		}
	}
	if !acls {
		// Only change to Open if we found something
		resp.Status.Open = findings.FindingOpen
	}
	return resp
}

func s3BucketACLChecks(s3Svc *s3.S3, s3BucketName string) bool {
	resp := true
	aclParams := &s3.GetBucketAclInput{
		Bucket: aws.String(s3BucketName), // Required
	}
	acl, err := s3Svc.GetBucketAcl(aclParams)
	if err != nil {
		fmt.Println(err.Error())
	}
	for grant := range acl.Grants {
		// ensure struct member exists (URI is only set when ID is not!)
		if acl.Grants[grant].Grantee.URI != nil {
			if *acl.Grants[grant].Grantee.URI == AllUsersURI {
				// All users has been granted permissiosn to the bucket
				resp = false
				fmt.Println("Failing check due to AllUsers having: ", *acl.Grants[grant].Permission)
			}
			if *acl.Grants[grant].Grantee.URI == AuthenticedUsersURI {
				// Auth'd users has been granted perms to Bucket
				resp = false
				fmt.Println("Failing check due to Auth'd users having: ", *acl.Grants[grant].Permission)
			}
		}
	}

	return resp
}
func s3BucketPolicyChecks(s3Svc *s3.S3, s3BucketName string) bool {
	resp := true

	policyParams := &s3.GetBucketPolicyInput{
		Bucket: aws.String(s3BucketName), // Required
	}
	policy, err := s3Svc.GetBucketPolicy(policyParams)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Decode JSON - note we throw away almost all of it here
	// and only keep the 3 fields we need
	var m S3ACL
	b := []byte(*policy.Policy) // Unmarshal requires byte array
	_ = json.Unmarshal(b, &m)

	for idx := range m.Statement {
		// ensure struct member exists
		if &m.Statement[idx].Principal != nil {
			// Check to make sure there no 'Allow' to '*' policy statement
			if m.Statement[idx].Principal == "*" && m.Statement[idx].Effect == "Allow" {
				fmt.Println("Failing because of bucket policy for *")
				resp = false
			}
		}
	}
	return resp
}

func ensureBucketLoggingEnabled(trails []*cloudtrail.Trail, s3Svc *s3.S3) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.6", Description: Finding2_6Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}
	for i := range trails {
		if trails[i].S3BucketName != nil {
			params := &s3.GetBucketLoggingInput{
				Bucket: aws.String(*trails[i].S3BucketName), // Required
			}
			loggingStatus, err := s3Svc.GetBucketLogging(params)
			if err != nil {
				panic(err)
			}
			if loggingStatus.LoggingEnabled != nil {
				resp.Status.Open = findings.FindingClosed
			}
		}
	}
	return resp
}

func ensureConfigEnabled(cs *configservice.ConfigService) findings.Finding {
	// TODO: Make multi-region enabled
	resp := findings.Finding{Name: "Finding 2.5", Description: Finding2_5Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}
	params := &configservice.DescribeConfigurationRecordersInput{}

	cr, err := cs.DescribeConfigurationRecorders(params)
	if err != nil {
		panic(err)
	}
	for i := range cr.ConfigurationRecorders {
		if *cr.ConfigurationRecorders[i].RecordingGroup.AllSupported && *cr.ConfigurationRecorders[i].RecordingGroup.IncludeGlobalResourceTypes {
			resp.Status.Open = findings.FindingClosed
		}
	}
	return resp
}

func ensureCMKRotationEnabled(kmsSvc *kms.KMS) findings.Finding {
	resp := findings.Finding{Name: "Finding 2.8", Description: Finding2_8Txt, Status: findings.Status{Checked: true, Open: findings.FindingOpen}, Notes: make(map[string]string)}

	listparams := &kms.ListKeysInput{}
	keys, err := kmsSvc.ListKeys(listparams)
	if err != nil {
		panic(err)
	}
	for k := range keys.Keys {
		params := &kms.GetKeyRotationStatusInput{
			KeyId: aws.String(*keys.Keys[k].KeyId), // Required
		}
		status, _ := kmsSvc.GetKeyRotationStatus(params)

		if status.KeyRotationEnabled != nil {
			isenabled := *status.KeyRotationEnabled
			if isenabled {
				resp.Status.Open = findings.FindingClosed
			}
		}

	}
	return resp
}
