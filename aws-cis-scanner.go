package main

import (
	"flag"
	"fmt"
	"html/template"
	"os"

	"github.com/adamcrosby/aws-cis-scanner/benchmark"
	"github.com/adamcrosby/aws-cis-scanner/utility/findings"
	"github.com/adamcrosby/aws-cis-scanner/utility/regions"
	"github.com/adamcrosby/aws-cis-scanner/utility/report"
	"github.com/adamcrosby/aws-cis-scanner/utility/services"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
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

func main() {
	var regionPtr string
	var arn string
	var externalID string

	const (
		defaultARN      = ""
		arnUsage        = "The ARN of the role you need to assume"
		defaultExtID    = ""
		extIDUsage      = "The ExternalID constraint, if applicable for the role you need to assume"
		region          = "us-east-1"
		defaultRegion   = regions.AllRegions
		regionFlagUsage = "AWS Region in standard shorthand format (eg: 'us-east-1' or 'us-west-2').  Default is \"us-east-1\"."
	)
	flag.StringVar(&regionPtr, "region", defaultRegion, regionFlagUsage)
	flag.StringVar(&regionPtr, "r", defaultRegion, regionFlagUsage+" (shorthand)")
	flag.StringVar(&arn, "arn", defaultARN, arnUsage)
	flag.StringVar(&externalID, "extid", defaultExtID, extIDUsage)
	flag.Parse()

	var regionsList []string

	switch regionPtr {
	case regions.CNNorth1:
		// if region is govcloud or china, special handling:
		fmt.Println("Isolated Regions (CN) not yet supported.")
		fmt.Println("If you need this support, please open a github issue.")
		os.Exit(1)
	case regions.GovCloud:
		regionsList = regions.GovRegions
	case regions.AllRegions:
		regionsList = regions.CommercialRegions
	default:
		// a region was actually specified in the config, so use it.
		regionsList = []string{regionPtr}
	}

	// Create a new session
	sess := session.Must(session.NewSession())

	benchmark := make(findings.Checks, findings.FindingsInCISBenchmark)

	for i := range regionsList {

		// Create services pointers for either option
		primaryConf := aws.Config{Region: aws.String(regionsList[i])}
		services := services.AWSServices{}
		services.IAM = iam.New(sess, &primaryConf)
		services.CloudTrail = cloudtrail.New(sess, &primaryConf)
		services.S3Primary = s3.New(sess, &primaryConf)
		services.Config = configservice.New(sess, &primaryConf)
		services.KMS = kms.New(sess, &primaryConf)
		services.CloudWatch = cloudwatch.New(sess, &primaryConf)
		services.CloudWatchLogs = cloudwatchlogs.New(sess, &primaryConf)
		services.SNS = sns.New(sess, &primaryConf)
		services.EC2 = ec2.New(sess, &primaryConf)
		if arn != "" {
			// Alt ARN is used
			altConf := createConfig(arn, externalID, regionsList[i], sess)
			services.S3Alt = s3.New(sess, &altConf)
		}

		benchmark = checkRegion(benchmark, services)
	}
	printTemplate(benchmark)
}

func printTemplate(checks findings.Checks) {
	templateString := report.ReportTemplateHTML

	tmpl := template.New("report template")
	tmpl = tmpl.Funcs(template.FuncMap{"statusReplace": report.StatusReplacer})

	tmpl, err := tmpl.Parse(templateString)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, checks)
	if err != nil {
		panic(err)
	}
}

func checkRegion(checks findings.Checks, services services.AWSServices) findings.Checks {

	/** iamSvc := services.IAM
	ctSvc := services.CloudTrail
	s3Svc := services.S3Primary
	cfSvc := services.Config
	kmsSvc := services.KMS
	cwlogsSvc := services.CloudWatchLogs
	cwSvc := services.CloudWatch
	snsSvc := services.SNS
	ec2Svc := services.EC2
	altS3Svc := services.S3Alt
	**/

	checks = benchmark.DoIAMChecks(services, checks)

	// Setup for the Logging section of checks (2.1 - 2.8)

	checks = benchmark.LoggingChecks(services, checks)
	checks = benchmark.MonitoringChecks(services, checks)
	checks = benchmark.DoNetworkChecks(services, checks)

	return checks
}

func createConfig(arn string, externalID string, region string, sess *session.Session) aws.Config {

	conf := aws.Config{Region: aws.String(region)}
	if arn != "" {
		// if ARN flag is passed in, we need to be able ot assume role here
		var creds *credentials.Credentials
		if externalID != "" {
			// If externalID flag is passed, we need to include it in credentials struct
			creds = stscreds.NewCredentials(sess, arn, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = &externalID
			})
		} else {
			creds = stscreds.NewCredentials(sess, arn, func(p *stscreds.AssumeRoleProvider) {})
		}
		conf.Credentials = creds
	}
	return conf
}
