package accounts

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
)

//"github.com/adamcrosby/aws-cis-scanner/benchmark"

// Account holds account information retrieved from IAM for a single account
type Account map[string]string

/*
GetAccountInformation retrieves all IAM related information from AWS APIs
   - Requires access to GetCredentialReport, GetAccountPasswordPolicy, ListUsers, and ListUserPolicies IAM API calls
   - Modifies the struct in place
*/
func getAccountInformation(IAM *iam.IAM) {

	var params *iam.GenerateCredentialReportInput
	status, err := IAM.GenerateCredentialReport(params)
	if err != nil {
		panic(err)
	}

	if *status.State == iam.ReportStateTypeComplete {
		//fmt.Println("Credential Report exists, downloading now.")
	} else {
		//fmt.Println("Credential Report doesn't exist, waiting 5 seconds and retrying.")
		time.Sleep(5 * time.Second)
		status, err = IAM.GenerateCredentialReport(params)
		if err != nil {
			panic(err)
		}
		// Check status again, after 5 second pause, bailing out entirely if it's not ready yet (should only take 1-2 seconds unless huge IAM install)
		if *status.State != iam.ReportStateTypeComplete {
			fmt.Println("Credential Report still not available, please try again later.")
			os.Exit(1) // exit with failure notice to shell
		}
	}
}

/*
GetDecodedCredentialReport retrieves and decodes the credential report for a given Account*/
func getDecodedCredentialReport(IAM *iam.IAM) []byte {
	getAccountInformation(IAM)
	var params *iam.GetCredentialReportInput
	report, err := IAM.GetCredentialReport(params)

	encoded := base64.StdEncoding.EncodeToString(report.Content)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Println("Error base64 decoding CredentialReport:", err)
		os.Exit(1)
	}

	return decoded
}

func mapReport(report []byte) []Account {

	r := csv.NewReader(strings.NewReader(string(report)))
	header, _ := r.Read()

	records, err := r.ReadAll()
	if err != nil {
		fmt.Println("Error reading from decoded CSV", err)
		os.Exit(1)
	}
	accounts := make([]Account, len(records))
	for key := range records {
		account := make(Account)
		for i := 0; i < len(records[key]); i++ {
			account[header[i]] = records[key][i]
			accounts[key] = account
		}

	}
	return accounts
}

/*
GetAccounts does things gets accounts yo
*/
func GetAccounts(IAM *iam.IAM) []Account {
	decode := getDecodedCredentialReport(IAM)
	accounts := mapReport(decode)
	return accounts

}

/*
GetPasswordPolicy retrieves password policy from IAM
*/
func GetPasswordPolicy(IAM *iam.IAM) iam.PasswordPolicy {
	var params *iam.GetAccountPasswordPolicyInput
	response, err := IAM.GetAccountPasswordPolicy(params)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if origErr := awsErr.OrigErr(); origErr != nil {
				fmt.Println("Error: ", origErr)
			}
			if awsErr.Code() == "NoSuchEntity" {
				return iam.PasswordPolicy{}
			}
			os.Exit(1)
		} else {
			fmt.Println("Error retrieving password policy: ", err.Error())
		}
	}
	return *response.PasswordPolicy
}

/*
UserPoliciesExist determines if any user policies exist
Check 1.15
*/
func UserPoliciesExist(a []Account, IAM *iam.IAM) bool {
	resp := true // default to pass, and only overide it on inspection below
	for i := range a {
		// get policies for each ARN
		if a[i]["user"] == "<root_account>" {
			// if User is '<root_account>' skip it - root can't have policies attached
			continue
		}
		resp = checkInlinePolicies(a[i], IAM)
		resp = checkManagedPolicies(a[i], IAM)
	}

	return resp
}

func checkInlinePolicies(a Account, IAM *iam.IAM) bool {
	resp := true // default to pass, and only overide it on inspection below

	// Create input param structure
	params := iam.ListUserPoliciesInput{
		UserName: aws.String(a["user"]), // Required
		MaxItems: aws.Int64(1)}

	// Check for inline policies
	policy, err := IAM.ListUserPolicies(&params)
	if err != nil {
		fmt.Println("Error retrieving policy for ", a["user"])
		fmt.Println("Error was: ", err.Error())
		return resp
	}

	// IAM returns an empty list for accounts that have policies attached.
	if len(policy.PolicyNames) > 0 {
		//if ANY account has a policy attached, this sets response to false to fail the check
		resp = false
	}
	return resp
}

func checkManagedPolicies(a Account, IAM *iam.IAM) bool {
	resp := true // default to pass, and only overide it on inspection below

	// Create input param structure
	params := iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(a["user"]), // Required
		MaxItems: aws.Int64(1)}

	// Check for inline policies
	policy, err := IAM.ListAttachedUserPolicies(&params)
	if err != nil {
		fmt.Println("Error retrieving policy for ", a["user"])
		fmt.Println("Error was: ", err.Error())
		return resp
	}

	// IAM returns an empty list for accounts that have policies attached.
	if len(policy.AttachedPolicies) > 0 {
		//if ANY account has a policy attached, this sets response to false to fail the check
		resp = false
	}
	return resp
}
