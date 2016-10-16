package benchmark

import (
	"fmt"

	"github.com/adamcrosby/aws-cis-scanner/utility/findings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const port22Ingress = "Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0'"
const port3389Ingress = "Name=ip-permission.from-port,Values=3389 Name=ip-permission.to-port,Values=3389 Name=ip-permission.cidr,Values='0.0.0.0/0'"

/*
DoNetworkChecks runs the network checks from Section 4 of the benchmark
*/
func DoNetworkChecks(ec2Svc *ec2.EC2, checks findings.Checks) findings.Checks {
	// Do some funky legwork here as this is called multiple times for each region.  ANY
	// failure in ANY region fails the check entirely, so ensure it's not accidentally reset
	if chk := checks["Finding 4.1"].Status.Checked; chk {
		if checks["Finding 4.1"].Status.Open == findings.FindingClosed {
			// Finding has been checked but is not already marked open: leave it as such.
			open, sgs := checkSinglePortOpenToWorld(ec2Svc, "22")
			checks["Finding 4.1"] = findings.Finding{
				Name:        "Finding 4.1",
				Description: Finding4_1Txt,
				Status: findings.Status{
					Open:    open,
					Checked: true},
				Notes: make(map[string]string)}
			checks["Finding 4.1"].Notes["User"] = checks["Finding 4.1"].Notes["User"] + sgs
		} //else the finding is unknown or open, just leave it.
	} else {
		// the check hasn't been run, so just run it
		open, sgs := checkSinglePortOpenToWorld(ec2Svc, "22")
		checks["Finding 4.1"] = findings.Finding{
			Name:        "Finding 4.1",
			Description: Finding4_1Txt,
			Status: findings.Status{
				Open:    open,
				Checked: true},
			Notes: make(map[string]string)}
		checks["Finding 4.1"].Notes["User"] = checks["Finding 4.1"].Notes["User"] + sgs
	}
	// Redo the same check to ensure 4.2 isn't reset either.
	if chk := checks["Finding 4.2"].Status.Checked; chk {
		if checks["Finding 4.2"].Status.Open == findings.FindingClosed {
			open, sgs := checkSinglePortOpenToWorld(ec2Svc, "3389")
			checks["Finding 4.2"] = findings.Finding{
				Name:        "Finding 4.2",
				Description: Finding4_2Txt,
				Status: findings.Status{
					Open:    open,
					Checked: true},
				Notes: make(map[string]string)}
			checks["Finding 4.2"].Notes["User"] = sgs
		}
	} else {
		open, sgs := checkSinglePortOpenToWorld(ec2Svc, "3389")
		checks["Finding 4.2"] = findings.Finding{
			Name:        "Finding 4.2",
			Description: Finding4_2Txt,
			Status: findings.Status{
				Open:    open,
				Checked: true},
			Notes: make(map[string]string)}
		checks["Finding 4.2"].Notes["User"] = sgs
	}

	checks["Finding 4.3"] = findings.Finding{
		Name:        "Finding 4.3",
		Description: Finding4_3Txt,
		Status: findings.Status{
			Open:    checkFlowLogs(ec2Svc),
			Checked: true}}

	checks["Finding 4.4"] = findings.Finding{
		Name:        "Finding 4.4",
		Description: Finding4_4Txt,
		Status: findings.Status{
			Open:    restrictDefaultSG(ec2Svc),
			Checked: true}}

	return checks
}

func checkSinglePortOpenToWorld(ec2Svc *ec2.EC2, portNum string) (string, string) {

	ipFrom := ec2.Filter{
		Name:   aws.String("ip-permission.to-port"),
		Values: []*string{aws.String(portNum)}}
	ipTo := ec2.Filter{
		Name:   aws.String("ip-permission.to-port"),
		Values: []*string{aws.String(portNum)}}
	ipCidr := ec2.Filter{
		Name:   aws.String("ip-permission.cidr"),
		Values: []*string{aws.String("0.0.0.0/0")}}
	filters := []*ec2.Filter{&ipFrom, &ipTo, &ipCidr}

	query := &ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	}
	sgs, err := ec2Svc.DescribeSecurityGroups(query)
	if err != nil {
		panic(err)
	}
	sgList := ""
	if len(sgs.SecurityGroups) > 0 {

		for x := range sgs.SecurityGroups {
			if sgList == "" {
				sgList = fmt.Sprintf("%s", *sgs.SecurityGroups[x].GroupName)
			} else {
				sgList = fmt.Sprintf("%s, %s", sgList, *sgs.SecurityGroups[x].GroupName)
			}
		}

		return findings.FindingOpen, sgList // At least one SG has port 22 open to the world, so check passes
	} // otherwise, resp stays true, check passes
	return findings.FindingClosed, ""
}

func checkFlowLogs(ec2Svc *ec2.EC2) string {
	// The Audit check text doesn't specify what kind, how many or anything
	// Just that 'a vpc' has 'flowlogging' with 'status'= 'ACTIVE', so
	// loop through all the flowlogs and if any have 'active', return that.
	resp := false

	param := &ec2.DescribeFlowLogsInput{}
	flows, err := ec2Svc.DescribeFlowLogs(param)
	if err != nil {
		panic(err)
	}
	for f := range flows.FlowLogs {
		if *flows.FlowLogs[f].FlowLogStatus == "ACTIVE" {
			resp = true
			break
		}
	}
	if resp {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

func restrictDefaultSG(ec2Svc *ec2.EC2) string {
	resp := false
	defaultGroupName := ec2.Filter{
		Name:   aws.String("group-name"),
		Values: []*string{aws.String("default")}}

	filters := []*ec2.Filter{&defaultGroupName}

	query := &ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	}
	sgs, err := ec2Svc.DescribeSecurityGroups(query)
	if err != nil {
		panic(err)
	}
	for g := range sgs.SecurityGroups {
		if sgs.SecurityGroups[g].IpPermissions == nil && sgs.SecurityGroups[g].IpPermissionsEgress == nil {
			resp = true
		}
	}
	if resp {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}
