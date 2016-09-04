package main

import (
	"flag"
	"fmt"
	"html/template"
	"os"

	"github.com/adamcrosby/aws-cis-scanner/benchmark"
	"github.com/adamcrosby/aws-cis-scanner/utility/accounts"
	"github.com/adamcrosby/aws-cis-scanner/utility/regions"
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
	var regionPtr string
	const (
		defaultRegion   = regions.USEast1
		regionFlagUsage = "AWS Region in standard shorthand format (eg: 'us-east-1' or 'us-west-2').  Default is \"us-east-1\"."
	)
	flag.StringVar(&regionPtr, "region", defaultRegion, regionFlagUsage)
	flag.StringVar(&regionPtr, "r", defaultRegion, regionFlagUsage+" (shorthand)")
	flag.Parse()

	// if region is govcloud or china, special handling:
	if regionPtr == regions.CNNorth1 {
		fmt.Println("Isolated Regions not yet supported.")
		os.Exit(1)
	}

	// figure out the list of regions to iterate over
	var regionsList []string
	if regionPtr == regions.GovCloud {
		regionsList = regions.GovRegions

	} else {

		regionsList = regions.CommercialRegions

	}

	// Create a new session
	sess, err := session.NewSession()
	if err != nil {
		panic(err)
	}

	status := benchmark.Status{}
	for i := range regionsList {
		fmt.Println("Region is: ", regionsList[i])
		conf := aws.Config{Region: aws.String(regionsList[i])}
		fmt.Printf("Conf says: %+v \n", conf)
		status = checkRegion(status, sess, conf)
	}

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

func checkRegion(status benchmark.Status, sess *session.Session, conf aws.Config) benchmark.Status {

	iamSvc := iam.New(sess, &conf)
	ctSvc := cloudtrail.New(sess, &conf)
	s3Svc := s3.New(sess, &conf)
	cfSvc := configservice.New(sess, &conf)
	kmsSvc := kms.New(sess, &conf)
	cwlogsSvc := cloudwatchlogs.New(sess, &conf)
	cwSvc := cloudwatch.New(sess, &conf)
	snsSvc := sns.New(sess, &conf)
	ec2Svc := ec2.New(sess, &conf)

	awsAccounts := accounts.GetAccounts(iamSvc)
	awsPasswordPolicy := accounts.GetPasswordPolicy(iamSvc)
	status.Finding1_15 = accounts.UserPoliciesExist(awsAccounts, iamSvc)
	status = benchmark.DoIAMChecks(status, awsAccounts, awsPasswordPolicy)

	// Setup for the Logging section of checks (2.1 - 2.8)

	status = benchmark.LoggingChecks(kmsSvc, cfSvc, s3Svc, ctSvc, status)
	status = benchmark.MonitoringChecks(snsSvc, cwSvc, cwlogsSvc, ctSvc, status)
	status = benchmark.DoNetworkChecks(ec2Svc, status)
	return status
}
