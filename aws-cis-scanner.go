package main

import (
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
	sess, err := session.NewSession()
	if err != nil {
		panic(err)
	}
	status := benchmark.Status{}
	IAM := iam.New(sess)

	awsAccounts := accounts.GetAccounts(IAM)
	awsPasswordPolicy := accounts.GetPasswordPolicy(IAM)
	status.Finding1_15 = accounts.UserPoliciesExist(awsAccounts, IAM)
	status = benchmark.DoIAMChecks(status, awsAccounts, awsPasswordPolicy)

	// Setup for the Logging section of checks (2.1 - 2.8)
	CT := cloudtrail.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	s3Svc := s3.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	cf := configservice.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	kmsSvc := kms.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	cwlogs := cloudwatchlogs.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	cw := cloudwatch.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	snsSvc := sns.New(sess, &aws.Config{Region: aws.String("us-east-1")})
	ec2Svc := ec2.New(sess, &aws.Config{Region: aws.String("us-east-1")})

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
