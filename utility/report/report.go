package report

import (
	"fmt"
	"html/template"
)

// StatusReplacer does string replacement for mah template
func StatusReplacer(args ...interface{}) template.HTML {
	ok := false
	var s string
	if len(args) == 1 {
		s, ok = args[0].(string)
	}
	if !ok {
		s = fmt.Sprint(args...)
	}

	if s == "false" {
		return template.HTML("<h3 class=\"label label-danger\">Fail</h3>")
	}
	if s == "true" {
		return template.HTML("<h3 class=\"label label-success\">Pass</h3>")
	}
	return template.HTML("ERROR")
}

// ReportTemplateHTML is the report in html format
const ReportTemplateHTML = `<!DOCTYPE html>
<html>
<head>
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

<!-- Optional theme -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">

<!-- Latest compiled and minified JavaScript -->
<script   src="https://code.jquery.com/jquery-3.1.0.slim.min.js"   integrity="sha256-cRpWjoSOw5KcyIOaZNo4i6fZ9tKPhYYb6i5T9RSVJG8="   crossorigin="anonymous"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.2.2/Chart.bundle.min.js" integrity="sha256-0mJl0YDK3QdHZZsN7e4XmWNvoGTJJZjZF6eSCECmysM=" crossorigin="anonymous"></script>

<script>
	function GetCount(findings){
		var trueCount = 0;
		console.log(findings);
		console.log(findings.length);
		for (var i=0; i < findings.length; i++){
			if (findings[i]){
				trueCount++;
			}
		}
		return trueCount;
	}
	var section1 = Array({{ .Finding1_1 }},{{ .Finding1_2 }},{{.Finding1_3}},{{.Finding1_4}},{{.Finding1_5}},{{.Finding1_6}},{{.Finding1_7}},{{.Finding1_8}},{{.Finding1_9}},{{.Finding1_10}},{{.Finding1_11}},{{.Finding1_12}},{{.Finding1_13}},{{.Finding1_14}},{{.Finding1_15}})
	var section1PassCount = GetCount(section1)
	var section1FailCount = section1.length - section1PassCount

	var section2 = Array({{.Finding2_1}},{{.Finding2_2}},{{.Finding2_3}},{{.Finding2_4}},{{.Finding2_5}},{{.Finding2_6}},{{.Finding2_7}},{{.Finding2_8}})
	var section2PassCount = GetCount(section2)
	var section2FailCount = section2.length - section2PassCount

	var section3 = Array({{.Finding3_1}},{{.Finding3_2}},{{.Finding3_3}},{{.Finding3_4}},{{.Finding3_5}},{{.Finding3_6}},{{.Finding3_7}},{{.Finding3_8}},{{.Finding3_9}},{{.Finding3_10}},{{.Finding3_11}},{{.Finding3_12}},{{.Finding3_13}},{{.Finding3_14}},{{.Finding3_15}},{{.Finding3_16}})
	var section3PassCount = GetCount(section3)
	var section3FailCount = section3.length - section3PassCount

	var section4 = Array({{ .Finding4_1 }},{{ .Finding4_2 }},{{ .Finding4_3 }},{{ .Finding4_4 }})
	var section4PassCount = GetCount(section4)
	var section4FailCount = section4.length - section4PassCount
</script>





</head>
<nav class="navbar navbar-inverse">
   <div class="container">
     <div class="navbar-header">
       <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target=".navbar-collapse">
         <span class="sr-only">Toggle navigation</span>
         <span class="icon-bar"></span>
         <span class="icon-bar"></span>
         <span class="icon-bar"></span>
       </button>
       <a class="navbar-brand" href="#">CIS Benchmark Report</a>
     </div>
     <div class="navbar-collapse collapse">
       <ul class="nav navbar-nav">
         <li class="active"><a href="#">Report</a></li>
         <li><a href="https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf">Reference</a></li>
         <li><a href="#about">About</a></li>
         <li><a href="https://www.github.com/adamcrosby/aws-cis-scanner">Github</a></li>
       </ul>
     </div><!--/.nav-collapse -->
   </div>
 </nav>


<body>
<div class="container"><div class="row">

<div class="col-lg-3">
<canvas id="section1Chart" width="20" height="20"></canvas>
	<script>
		var ctxSection1 = document.getElementById("section1Chart");
		var data = {
		    labels: [
		        "Fail",
		        "Pass",
		        "Unchecked"
		    ],
		    datasets: [
		        {
		            data: [section1FailCount, section1PassCount, 1],
		            backgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ],
		            hoverBackgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ]
		        }]
		};
		var myPieChart = new Chart(ctxSection1,{
		    type: 'pie',
		    data: data,
		    options: {
		        title: {
		                display: true,
		                text: 'Section 1',
		        },
						legend: {
										display: false,
						}
					}
		});
	</script>
</div>

<div class="col-lg-3">
<canvas id="section2Chart" width="20" height="20"></canvas>
	<script>
		var ctxSection2 = document.getElementById("section2Chart");
		var data = {
		    labels: [
		        "Fail",
		        "Pass",
		        "Unchecked"
		    ],
		    datasets: [
		        {
		            data: [section2FailCount, section2PassCount, 0],
		            backgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ],
		            hoverBackgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ]
		        }]
		};
		var myPieChart = new Chart(ctxSection2,{
		    type: 'pie',
		    data: data,
		    options: {
		        title: {
		                display: true,
		                text: 'Section 2',
		        },
						legend: {
										display: false,
						}
		    }
		});
	</script>
</div>

<div class="col-lg-3">
<canvas id="section3Chart" width="20" height="20"></canvas>
	<script>
		var ctxSection3 = document.getElementById("section3Chart");
		var data = {
		    labels: [
		        "Fail",
		        "Pass",
		        "Unchecked"
		    ],
		    datasets: [
		        {
		            data: [section3FailCount, section3PassCount, 2],
		            backgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ],
		            hoverBackgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ]
		        }]
		};
		var myPieChart = new Chart(ctxSection3,{
		    type: 'pie',
		    data: data,
		    options: {
		        title: {
		                display: true,
		                text: 'Section 3',
		        },
						legend: {
										display: false,
						}
		    }
		});
	</script>
</div>


<div class="col-lg-3">
<canvas id="section4Chart" width="20" height="20"></canvas>
	<script>
		var ctxSection4 = document.getElementById("section4Chart");
		var data = {
		    labels: [
		        "Fail",
		        "Pass",
		        "Unchecked"
		    ],
		    datasets: [
		        {
		            data: [section4FailCount, section4PassCount, 0],
		            backgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ],
		            hoverBackgroundColor: [
		                "#FF6384",
		                "rgb(92, 184, 92)",
		                "#FFCE56"
		            ]
		        }]
		};
		var myPieChart = new Chart(ctxSection4,{
		    type: 'pie',
		    data: data,
		    options: {
		        title: {
		                display: true,
		                text: 'Section 4',
		        },
						legend: {
										display: false,
						}
		    }
		});
	</script>
</div>

</div>
<div class="row">
<div class="text-center col-lg-12"><h4>
Fail: <span style="background: #FF6384;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Pass: <span style="background: rgb(92, 184, 92);">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Unchecked: <span style="background: #FFCE56;">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</h4>
</div>

</div></div>

<div class="container">
<h1>Section 1: Identity and access management</h1>
<table class="table table-striped table-hover table-condensed">
<thead>
<tr><th width="8%">Finding</th><th width="8%">Status</th><th>Title</th></tr>
</thead>
<tbody >
<tr><td>Finding 1.1</td><td>{{ .Finding1_1 | statusReplace}}</td><td>Avoid the use of the 'root' account (Scored)</td></tr>
 <tr><td>Finding 1.2</td><td>{{ .Finding1_2 | statusReplace }}</td><td>Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)</td></tr>
 <tr><td>Finding 1.3</td><td>{{ .Finding1_3 | statusReplace }}</td><td>Ensure credentials unused for 90 days or greater are disabled (Scored)</td></tr>
 <tr><td>Finding 1.4</td><td>{{ .Finding1_4 | statusReplace }}</td><td>Ensure access keys are rotated every 90 days or less (Scored)</td></tr>
 <tr><td>Finding 1.5</td><td>{{ .Finding1_5 | statusReplace }}</td><td>Ensure IAM password policy requires at least one uppercase letter (Scored)</td></tr>
 <tr><td>Finding 1.6</td><td>{{ .Finding1_6 | statusReplace }}</td><td>Ensure IAM password policy require at least one lowercase letter (Scored)</td></tr>
 <tr><td>Finding 1.7</td><td>{{ .Finding1_7 | statusReplace }}</td><td>Ensure IAM password policy require at least one symbol (Scored)</td></tr>
 <tr><td>Finding 1.8</td><td>{{ .Finding1_8 | statusReplace }}</td><td>Ensure IAM password policy require at least one number (Scored)</td></tr>
 <tr><td>Finding 1.9</td><td>{{ .Finding1_9 | statusReplace }}</td><td>Ensure IAM password policy requires minimum length of 14 or greater (Scored)</td></tr>
 <tr><td>Finding 1.10</td><td>{{ .Finding1_10 | statusReplace }}</td><td>Ensure IAM password policy prevents password reuse (Scored)</td></tr>
 <tr><td>Finding 1.11</td><td>{{ .Finding1_11 | statusReplace }}</td><td>Ensure IAM password policy expires passwords within 90 days or less (Scored)</td></tr>
 <tr><td>Finding 1.12</td><td>{{ .Finding1_12 | statusReplace }}</td><td>Ensure no root account access key exists (Scored)</td></tr>
 <tr><td>Finding 1.13</td><td>{{ .Finding1_13 | statusReplace }}</td><td>Ensure hardware MFA is enabled for the 'root' account (Scored)</td></tr>
 <tr><td>Finding 1.14</td><td><h3 class="label label-warning">Not Checked</h3></td><td>Ensure security questions are registered in the AWS account (Not Scored) <span class="label label-info"><a href="#note1">Note 1</span></td></tr>
 <tr><td>Finding 1.15</td><td>{{ .Finding1_15 | statusReplace }}</td><td>Ensure IAM policies are attached only to groups or roles (Scored)</td></tr>
</tbody>
</table>

<h1>Section 2: Logging</h1>

<table class="table table-striped table-hover table-condensed">
<thead>
<tr><th width="8%">Finding</th><th width="8%">Status</th><th>Title</th></tr>
</thead>
<tbody>
 <tr><td>Finding 2.1</td><td>{{	.Finding2_1 | statusReplace }}</td><td>Ensure CloudTrail is enabled in all regions (Scored)</td></tr>
 <tr><td>Finding 2.2</td><td>{{	.Finding2_2 | statusReplace }}</td><td>Ensure CloudTrail log file validation is enabled (Scored)</td></tr>
 <tr><td>Finding 2.3</td><td>{{	.Finding2_3 | statusReplace }}</td><td>Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)</td></tr>
 <tr><td>Finding 2.4</td><td>{{	.Finding2_4 | statusReplace }}</td><td>Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)</td></tr>
 <tr><td>Finding 2.5</td><td>{{	.Finding2_5 | statusReplace }}</td><td>Ensure AWS Config is enabled in all regions (Scored)</td></tr>
 <tr><td>Finding 2.6</td><td>{{	.Finding2_6 | statusReplace }}</td><td>Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)</td></tr>
 <tr><td>Finding 2.7</td><td>{{	.Finding2_7 | statusReplace }}</td><td>Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)</td></tr>
 <tr><td>Finding 2.8</td><td>{{	.Finding2_8 | statusReplace }}</td><td>Ensure rotation for customer created CMKs is enabled (Scored)</td></tr>
</tbody>
</table>

<h1>Section 3: Monitoring</h1>
<table class="table table-striped table-hover table-condensed">
<thead>
<tr><th width="8%">Finding</th><th width="8%">Status</th><th>Title</th></tr>
</thead>
<tbody>
 <tr><td>Finding 3.1  </td><td>{{	.Finding3_1  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)</td></tr>
 <tr><td>Finding 3.2  </td><td>{{	.Finding3_2  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)</td></tr>
 <tr><td>Finding 3.3  </td><td>{{	.Finding3_3  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for usage of 'root' account (Scored)</td></tr>
 <tr><td>Finding 3.4  </td><td>{{	.Finding3_4  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for IAM policy changes (Scored)</td></tr>
 <tr><td>Finding 3.5  </td><td>{{	.Finding3_5  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for CloudTrail configuration changes</td></tr>
 <tr><td>Finding 3.6  </td><td>{{	.Finding3_6  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)</td></tr>
 <tr><td>Finding 3.7  </td><td>{{	.Finding3_7  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)</td></tr>
 <tr><td>Finding 3.8  </td><td>{{	.Finding3_8  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)</td></tr>
 <tr><td>Finding 3.9  </td><td>{{	.Finding3_9  | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for AWS Config configuration changes</td></tr>
 <tr><td>Finding 3.10 </td><td>{{	.Finding3_10 | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for security group changes (Scored)</td></tr>
 <tr><td>Finding 3.11 </td><td>{{	.Finding3_11 | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)</td></tr>
 <tr><td>Finding 3.12 </td><td>{{	.Finding3_12 | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for changes to network gateways</td></tr>
 <tr><td>Finding 3.13 </td><td>{{	.Finding3_13 | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for route table changes (Scored)</td></tr>
 <tr><td>Finding 3.14 </td><td>{{	.Finding3_14 | statusReplace }}</td><td>Ensure a log metric filter and alarm exist for VPC changes (Scored)</td></tr>
 <tr><td>Finding 3.15 </td><td><h3 class="label label-warning">Not Checked</h3></td><td>Ensure security contact information is registered (Scored) <span class="label label-info"><a href="#note1">Note 1</span></td></tr>
 <tr><td>Finding 3.16 </td><td><h3 class="label label-warning">Not Checked</h3></td><td>Ensure appropriate subscribers to each SNS topic (Not Scored) <span class="label label-info"><a href="#note2">Note 2</span></td></tr>
</tbody>
</table>

<h1>Section 4: Networking</h1>
<table class="table table-striped table-hover table-condensed">
<thead>
<tr><th width="8%">Finding</th><th width="8%">Status</th><th>Title</th></tr>
</thead>
<tbody>
 <tr><td>Finding 4.1</td><td>{{	.Finding4_1 | statusReplace }}</td><td>Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)</td></tr>
 <tr><td>Finding 4.2</td><td>{{	.Finding4_2 | statusReplace }}</td><td>Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)</td></tr>
 <tr><td>Finding 4.3</td><td>{{	.Finding4_3 | statusReplace }}</td><td>Ensure VPC Flow Logging is Enabled in all Applicable Regions (Scored)</td></tr>
 <tr><td>Finding 4.4</td><td>{{	.Finding4_4 | statusReplace }}</td><td>Ensure the default security group restricts all traffic (Scored)</td></tr>
</tbody>
</table>
</div>
<div class="container">
<ol>
<li><a name="note1"></a>Note 1: This item is not possible to programatically check/verify</li>
<li><a name="note2"></a>Note 2: This item must be manually checked to ensure correctness (specifically, if the subscribers are appropriate)</li>
</ol>
</div>
<div class="container">
<hr />
<div class="well">
<a name="about"></a>
<h2>About</h2>
<p>This report was generated by the AWS CIS Benchmark Scanner v0.2. &copy; 2016 Adam Crosby</p>
<p>The AWS CIS Benchmark content is &copy; Center for Internet Security - <a href="http://benchmarks.cisecurity.org">http://benchmarks.cisecurity.org</a></p>
<p>The AWS CIS Benchmark is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public License. The link to the license terms can be found at <a href="https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode">https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode</a></p>
</div>
</div>

</body>
</html>
`
