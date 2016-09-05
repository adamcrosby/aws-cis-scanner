package benchmark

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const port22Ingress = "Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0'"
const port3389Ingress = "Name=ip-permission.from-port,Values=3389 Name=ip-permission.to-port,Values=3389 Name=ip-permission.cidr,Values='0.0.0.0/0'"

/*
DoNetworkChecks runs the network checks from Section 4 of the benchmark
*/
func DoNetworkChecks(ec2Svc *ec2.EC2, s Status) Status {
	// Only run this check if it hasn't failed already
	if s.Finding4_1 {
		s.Finding4_1 = checkSinglePortOpenToWorld(ec2Svc, "22")
	}
	// Only run this check if it hasn't failed already
	if s.Finding4_2 {
		s.Finding4_2 = checkSinglePortOpenToWorld(ec2Svc, "3389")
	}

	s.Finding4_3 = checkFlowLogs(ec2Svc)
	s.Finding4_4 = restrictDefaultSG(ec2Svc)
	return s
}

func checkSinglePortOpenToWorld(ec2Svc *ec2.EC2, portNum string) bool {
	resp := true // default to pass

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
		fmt.Println(err.Error())
	}
	if len(sgs.SecurityGroups) > 0 {
		resp = true // At least one SG has port 22 open to the world, so check passes
	} // otherwise, resp stays true, check passes
	return resp
}

func checkFlowLogs(ec2Svc *ec2.EC2) bool {
	// The Audit check text doesn't specify what kind, how many or anything
	// Just that 'a vpc' has 'flowlogging' with 'status'= 'ACTIVE', so
	// loop through all the flowlogs and if any have 'active', return that.
	resp := false

	param := &ec2.DescribeFlowLogsInput{}
	flows, err := ec2Svc.DescribeFlowLogs(param)
	if err != nil {
		fmt.Println(err.Error())
	}
	for f := range flows.FlowLogs {
		if *flows.FlowLogs[f].FlowLogStatus == "ACTIVE" {
			resp = true
			break
		}
	}
	return resp
}

func restrictDefaultSG(ec2Svc *ec2.EC2) bool {
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
		fmt.Println(err.Error())
	}
	for g := range sgs.SecurityGroups {
		if sgs.SecurityGroups[g].IpPermissions == nil && sgs.SecurityGroups[g].IpPermissionsEgress == nil {
			resp = true
		}
	}
	return resp
}
