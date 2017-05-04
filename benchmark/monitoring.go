package benchmark

import (
	"fmt"
	"strings"

	"github.com/adamcrosby/aws-cis-scanner/utility/findings"
	"github.com/adamcrosby/aws-cis-scanner/utility/services"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/sns"
)

// FilterPatterns contains array of filtering statements reference dby Section 3 Monitoring
var FilterPatterns = [14]string{
	"{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }",                              // 3.1
	"{ $.userIdentity.sessionContext.attributes.mfaAuthenticated !=\"true\" }",                                         // 3.2
	"{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" } ", // 3.3
	"{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}", // 3.4
	"{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) ||($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }",                                                                                                                                                                                                                                                                                                                                                               // 3.5
	"{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }",                                                                                                                                                                                                                                                                                                                                                                                                                                          //3.6
	"{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))} }",                                                                                                                                                                                                                                                                                                                                                                                                                  // 3.7
	"{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }",                                                                                                                                  // 3.8
	"{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}",                                                                                                                                                                                                                                                                                                                      // 3.9
	"{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}",                                                                                                                                                                                                                                                 //3.10
	"{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }",                                                                                                                                                                                                                                                                      // 3.11
	"{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",                                                                                                                                                                                                                                                                    // 3.12
	"{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",                                                                                                                                                                                                                                                          // 3.13
	"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"}                                                                 //3.14

/*
MonitoringChecks runs the checks from 3.1-3.16 of the CIS benchmark
*/
func MonitoringChecks(services services.AWSServices, checks findings.Checks) findings.Checks {
	//func MonitoringChecks(snsSvc *sns.SNS, cw *cloudwatch.CloudWatch, cwlogs *cloudwatchlogs.CloudWatchLogs, ct *cloudtrail.CloudTrail, checks findings.Checks) findings.Checks {
	params := &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(true),
		TrailNameList:       []*string{},
	}
	trails, err := services.CloudTrail.DescribeTrails(params)

	if err != nil {
		panic(err)
	}

	checks["Finding 3.1"] = findings.Finding{
		Name:        "Finding 3.1",
		Description: Finding3_1Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[0], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.2"] = findings.Finding{
		Name:        "Finding 3.2",
		Description: Finding3_2Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[1], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.3"] = findings.Finding{
		Name:        "Finding 3.3",
		Description: Finding3_3Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[2], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.4"] = findings.Finding{
		Name:        "Finding 3.4",
		Description: Finding3_4Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[3], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.5"] = findings.Finding{
		Name:        "Finding 3.5",
		Description: Finding3_5Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[4], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.6"] = findings.Finding{
		Name:        "Finding 3.6",
		Description: Finding3_6Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[5], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.7"] = findings.Finding{
		Name:        "Finding 3.7",
		Description: Finding3_7Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[6], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.8"] = findings.Finding{
		Name:        "Finding 3.8",
		Description: Finding3_8Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[7], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.9"] = findings.Finding{
		Name:        "Finding 3.9",
		Description: Finding3_9Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[8], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.10"] = findings.Finding{
		Name:        "Finding 3.10",
		Description: Finding3_10Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[9], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.11"] = findings.Finding{
		Name:        "Finding 3.11",
		Description: Finding3_11Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[10], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.12"] = findings.Finding{
		Name:        "Finding 3.12",
		Description: Finding3_12Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[11], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.13"] = findings.Finding{
		Name:        "Finding 3.13",
		Description: Finding3_13Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[12], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}
	checks["Finding 3.14"] = findings.Finding{
		Name:        "Finding 3.14",
		Description: Finding3_14Txt,
		Status: findings.Status{
			Open:    filterAndAlarmExist(FilterPatterns[13], trails.TrailList, services.CloudWatchLogs, services.CloudWatch, services.SNS),
			Checked: true}}

	return checks
}

func filterAndAlarmExist(pattern string, trails []*cloudtrail.Trail, cwlogs *cloudwatchlogs.CloudWatchLogs, cw *cloudwatch.CloudWatch, snsSvc *sns.SNS) string {
	resp := false

	// Get list of all Cloud Trails
	for i := range trails {
		// Determine if Cloud trail is cloudwatch enabled (should be at least one, per section 2.4)
		if trails[i].CloudWatchLogsLogGroupArn != nil {

			// ARN of form: arn:aws:logs:us-east-1:1234567980:log-group:CloudTrail/DefaultLogGroup:*'
			// We need the 7th bit "CloudTrail/DefaultLogGroup" in this example, so split the string on ":"
			logGroupName := strings.Split(*trails[i].CloudWatchLogsLogGroupArn, ":")[6]
			metricFilterParams := &cloudwatchlogs.DescribeMetricFiltersInput{
				LogGroupName: &logGroupName,
			}
			// Get a list of metric filters on this particular Cloudtrail Logs entry, and match it against the target string
			// Then check to make sure there is an SNS alarm WITH at least one subscriber in order to pass the check
			filters, err := cwlogs.DescribeMetricFilters(metricFilterParams)
			if err != nil {
				fmt.Println(err.Error())
			}

			for filteridx := range filters.MetricFilters {
				// Check for pattern match
				//const pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
				filter := filters.MetricFilters[filteridx]
				resp = checkForPatternInFilter(pattern, filter, cw, snsSvc)
			}
		}
	}

	if resp {
		return findings.FindingClosed
	}
	return findings.FindingOpen

}

func atLeastOneSubscriber(snsSvc *sns.SNS, alertARN *string) bool {
	resp := false

	snsParam := &sns.ListSubscriptionsByTopicInput{
		TopicArn: alertARN,
	}
	subscribers, err := snsSvc.ListSubscriptionsByTopic(snsParam)
	if err != nil {
		fmt.Println(err.Error())
	}
	if len(subscribers.Subscriptions) > 0 {
		resp = true
	}
	return resp
}

func checkForPatternInFilter(pattern string, filter *cloudwatchlogs.MetricFilter, cw *cloudwatch.CloudWatch, snsSvc *sns.SNS) bool {
	resp := false
	if *filter.FilterPattern == pattern {

		metricName := filter.MetricTransformations[0].MetricName
		metricNamespace := filter.MetricTransformations[0].MetricNamespace

		params := &cloudwatch.DescribeAlarmsForMetricInput{
			MetricName: aws.String(*metricName),      // Required
			Namespace:  aws.String(*metricNamespace), // Required
		}
		alarms, alarmerr := cw.DescribeAlarmsForMetric(params)
		if alarmerr != nil {
			fmt.Println(alarmerr.Error())
		}

		for alarmidx := range alarms.MetricAlarms {
			// verify pointer is not null
			if alarms.MetricAlarms[alarmidx].AlarmActions != nil {
				resp = atLeastOneSubscriber(snsSvc, alarms.MetricAlarms[alarmidx].AlarmActions[0])
			}
		}
	}

	return resp
}
