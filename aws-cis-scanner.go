package main

import (
	"flag"
	"fmt"
	"html/template"
	"os"

	"github.com/adamcrosby/aws-cis-scanner/benchmark"
	"github.com/adamcrosby/aws-cis-scanner/utility/accounts"
	"github.com/adamcrosby/aws-cis-scanner/utility/report"
	"github.com/aws/aws-sdk-go/aws"
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
	//todo: determine which regions to run, for now just do commercial us-east
	//iam.New(session.New(), &aws.Config{Region: aws.String("us-east-1")}) call style
	var regionPtr string
	const (
		defaultRegion   = "us-east-1"
		regionFlagUsage = "AWS Region in standard shorthand format (eg: 'us-east-1' or 'us-west-2').  Default is \"us-east-1\"."
	)
	flag.StringVar(&regionPtr, "region", defaultRegion, regionFlagUsage)
	flag.StringVar(&regionPtr, "r", defaultRegion, regionFlagUsage+" (shorthand)")
	flag.Parse()

	sess, err := session.NewSession()
	if regionPtr == defaultRegion {
		fmt.Println("No region specified, defaulting to region: ", regionPtr)
	}

	if err != nil {
		panic(err)
	}
	status := benchmark.Status{}

	IAM := iam.New(sess, &aws.Config{Region: aws.String(regionPtr)})

	awsAccounts := accounts.GetAccounts(IAM)
	awsPasswordPolicy := accounts.GetPasswordPolicy(IAM)
	status.Finding1_15 = accounts.UserPoliciesExist(awsAccounts, IAM)
	status = benchmark.DoIAMChecks(status, awsAccounts, awsPasswordPolicy)

	// Setup for the Logging section of checks (2.1 - 2.8)
	CT := cloudtrail.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	s3Svc := s3.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	cf := configservice.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	kmsSvc := kms.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	cwlogs := cloudwatchlogs.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	cw := cloudwatch.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	snsSvc := sns.New(sess, &aws.Config{Region: aws.String(regionPtr)})
	ec2Svc := ec2.New(sess, &aws.Config{Region: aws.String(regionPtr)})

	status = benchmark.LoggingChecks(kmsSvc, cf, s3Svc, CT, status)
	status = benchmark.MonitoringChecks(snsSvc, cw, cwlogs, CT, status)
	status = benchmark.DoNetworkChecks(ec2Svc, status)

	//fmt.Println(status)

	printTemplate(status)
}

func printTemplate(status benchmark.Status) {
	templateString := report.ReportTemplateHTML

	tmpl := template.New("report template")
	tmpl = tmpl.Funcs(template.FuncMap{"statusReplace": report.StatusReplacer})

	tmpl, err := tmpl.Parse(templateString)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, status)
	if err != nil {
		panic(err)
	}
}
