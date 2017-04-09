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
		defaultRegion   = regions.AllRegions
		regionFlagUsage = "AWS Region in standard shorthand format (eg: 'us-east-1' or 'us-west-2').  Default is \"us-east-1\"."
	)
	flag.StringVar(&regionPtr, "region", defaultRegion, regionFlagUsage)
	flag.StringVar(&regionPtr, "r", defaultRegion, regionFlagUsage+" (shorthand)")
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
	sess, err := session.NewSession()
	if err != nil {
		panic(err)
	}

	benchmark := make(findings.Checks, findings.FindingsInCISBenchmark)

	for i := range regionsList {
		conf := aws.Config{Region: aws.String(regionsList[i])}
		benchmark = checkRegion(benchmark, sess, conf)
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

func checkRegion(checks findings.Checks, sess *session.Session, conf aws.Config) findings.Checks {

	iamSvc := iam.New(sess, &conf)
	ctSvc := cloudtrail.New(sess, &conf)
	s3Svc := s3.New(sess, &conf)
	cfSvc := configservice.New(sess, &conf)
	kmsSvc := kms.New(sess, &conf)
	cwlogsSvc := cloudwatchlogs.New(sess, &conf)
	cwSvc := cloudwatch.New(sess, &conf)
	snsSvc := sns.New(sess, &conf)
	ec2Svc := ec2.New(sess, &conf)

	checks = benchmark.DoIAMChecks(iamSvc, checks)

	// Setup for the Logging section of checks (2.1 - 2.8)

	checks = benchmark.LoggingChecks(kmsSvc, cfSvc, s3Svc, ctSvc, checks)
	checks = benchmark.MonitoringChecks(snsSvc, cwSvc, cwlogsSvc, ctSvc, checks)
	checks = benchmark.DoNetworkChecks(ec2Svc, checks)

	return checks
}
