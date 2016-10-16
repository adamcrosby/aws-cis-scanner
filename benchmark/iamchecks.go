package benchmark

import (
	"fmt"

	"github.com/adamcrosby/aws-cis-scanner/utility/accounts"
	"github.com/adamcrosby/aws-cis-scanner/utility/findings"
	"github.com/aws/aws-sdk-go/service/iam"
)

// Findings dictionary to hold findings
//type Findings map[string]bool

const credentialReportTrue = "true"
const credentialReportFalse = "false"
const rootAccountName = "<root_account>"
const days30 = 30 * 24
const days90 = 90 * 24
const days1 = 24
const finding1_11Val = 90
const finding1_9Val = 14

/*
DoIAMChecks runs the checks for section 1 of the CIS Benchmark and returns a single findings map
*/
func DoIAMChecks(iamSvc *iam.IAM, checks findings.Checks) findings.Checks {

	a := accounts.GetAccounts(iamSvc)
	pp := accounts.GetPasswordPolicy(iamSvc)

	checks["Finding 1.1"] = avoidRootAccountUse(a)
	checks["Finding 1.2"] = iamMFAEnabled(a)
	checks["Finding 1.3"] = areCredentialsDisabledAfter90Days(a)
	checks["Finding 1.4"] = areCredentialsRotatedWithin90Days(a)

	if pp != (iam.PasswordPolicy{}) {

		checks["Finding 1.5"] = findings.Finding{
			Name:        "Finding 1.5",
			Description: Finding1_5Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyUpperCase(pp)}}

		checks["Finding 1.6"] = findings.Finding{
			Name:        "Finding 1.6",
			Description: Finding1_6Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyLowerCase(pp)}}

		checks["Finding 1.7"] = findings.Finding{
			Name:        "Finding 1.7",
			Description: Finding1_7Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicySymbol(pp)}}

		checks["Finding 1.8"] = findings.Finding{
			Name:        "Finding 1.8",
			Description: Finding1_8Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyNumber(pp)}}

		checks["Finding 1.9"] = findings.Finding{
			Name:        "Finding 1.9",
			Description: Finding1_9Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyMinLength(pp)}}

		checks["Finding 1.10"] = findings.Finding{
			Name:        "Finding 1.10",
			Description: Finding1_10Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyPreventReuse(pp)}}

		checks["Finding 1.11"] = findings.Finding{
			Name:        "Finding 1.11",
			Description: Finding1_11Txt,
			Status: findings.Status{
				Checked: true,
				Open:    passPolicyMaxAge(pp)}}

	} else {
		checks["Finding 1.5"] = findings.Finding{
			Name:        "Finding 1.5",
			Description: Finding1_5Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.6"] = findings.Finding{
			Name:        "Finding 1.6",
			Description: Finding1_6Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.7"] = findings.Finding{
			Name:        "Finding 1.7",
			Description: Finding1_7Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.8"] = findings.Finding{
			Name:        "Finding 1.8",
			Description: Finding1_8Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.9"] = findings.Finding{
			Name:        "Finding 1.9",
			Description: Finding1_9Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.10"] = findings.Finding{
			Name:        "Finding 1.10",
			Description: Finding1_10Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
		checks["Finding 1.11"] = findings.Finding{
			Name:        "Finding 1.11",
			Description: Finding1_11Txt,
			Status: findings.Status{
				Checked: true,
				Open:    findings.FindingOpen}}
	}
	checks["Finding 1.12"] = ensureNoRootAccessKey(a)
	checks["Finding 1.13"] = ensureRootAccountMFAEnabled(a)

	checks["Finding 1.15"] = findings.Finding{
		Name:        "Finding 1.15",
		Description: Finding1_15Txt,
		Status: findings.Status{
			Checked: true,
			Open:    accounts.UserPoliciesExist(a, iamSvc)}}
	return checks
}

/*
Check 1.5 - # of upper case characters
*/
func passPolicyUpperCase(pp iam.PasswordPolicy) string {
	if *pp.RequireUppercaseCharacters {
		return findings.FindingClosed
	}
	return findings.FindingOpen

}

/*
Check 1.6 - # of lower case characters
*/
func passPolicyLowerCase(pp iam.PasswordPolicy) string {
	if *pp.RequireLowercaseCharacters {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

/*
Check 1.7 - # of symbol characters
*/
func passPolicySymbol(pp iam.PasswordPolicy) string {
	if *pp.RequireSymbols {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

/*
Check 1.8 - # of digit/number characters
*/
func passPolicyNumber(pp iam.PasswordPolicy) string {
	if *pp.RequireNumbers {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

/*
Check 1.9 - minimum password length
*/
func passPolicyMinLength(pp iam.PasswordPolicy) string {
	if *pp.MinimumPasswordLength >= finding1_9Val {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

/*
Check 1.10 - password reuse prevention
*/
func passPolicyPreventReuse(pp iam.PasswordPolicy) string {
	if pp.PasswordReusePrevention != nil {
		if *pp.PasswordReusePrevention != 0 {
			return findings.FindingClosed
		}

	}
	return findings.FindingOpen
}

/*
Check 1.11 - max password age
*/
func passPolicyMaxAge(pp iam.PasswordPolicy) string {
	if *pp.ExpirePasswords && (*pp.MaxPasswordAge > finding1_11Val) {
		return findings.FindingClosed
	}
	return findings.FindingOpen
}

/*
Check 1.2 - Ensure MFA is enabled for all iam users with passwords
*/
func iamMFAEnabled(a []accounts.Account) findings.Finding {
	// Iterate over each account in the list
	resp := findings.Finding{Name: "Finding 1.2", Description: Finding1_2Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}

	for i := range a {
		//fmt.Printf("Processing username: %s\n", a[i]["user"])
		// exclude <root_user> here, as it is not an IAM user
		if a[i]["user"] == rootAccountName {
			//fmt.Println("Root account, skipping")
			continue
		} else {
			/* Check 1.2 requires all IAM users (ie: non root account) who
			   have a password to also have an active MFA token.  If the user has no password,
			   we dont' care, and if the user has password AND mfa we don't care, so just fail
			   the password + no mfa state and pass the rest
			*/
			if a[i]["password_enabled"] == credentialReportTrue && a[i]["mfa_active"] == credentialReportFalse {
				//fmt.Printf("User: %s has password but no MFA", a[i]["user"])
				resp.Status.Open = findings.FindingOpen
				resp.Notes["User"] = fmt.Sprintf("Account %s has password but no MFA", a[i]["user"])
			} else {
				//fmt.Printf("User: %s has no password, or has password and MFA\n", a[i]["user"])
				resp.Status.Open = findings.FindingClosed
			}
		}

	}
	return resp
}

/*
Check 1.12 - ensure no root access key exists
*/
func ensureNoRootAccessKey(a []accounts.Account) findings.Finding {
	// Iterate over each account in the list
	resp := findings.Finding{Name: "Finding 1.12", Description: Finding1_12Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}
	for i := range a {
		//fmt.Printf("Processing username: %s\n", a[i]["user"])
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {

			if a[i]["access_key_1_active"] == credentialReportTrue || a[i]["access_key_2_active"] == credentialReportTrue {
				//fmt.Println("Root account has an active access key")
				// resp is false because this check FAILS if either of these conditions are true
				resp.Notes["User"] = fmt.Sprintf("Root Account has an active access key.")
				resp.Status.Open = findings.FindingOpen
			} else {
				// Root does not have an active access key
				//fmt.Println("Root account does not have an active access key")
				resp.Status.Open = findings.FindingClosed
			}
		} else {
			// skip to next user if not <root_user> here
			continue
		}
	}
	return resp
}

/*
Check 1.13 ensure MFA enabled for root account
*/
func ensureRootAccountMFAEnabled(a []accounts.Account) findings.Finding {
	// Iterate over each account in the list
	resp := findings.Finding{Name: "Finding 1.13", Description: Finding1_13Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}
	for i := range a {
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {
			//fmt.Println("Root account, chekcing")
			if a[i]["mfa_active"] == credentialReportTrue {
				// // Root has an MFA token, check passes
				resp.Status.Open = findings.FindingClosed
			} else {
				// Root does not have an MFA token, check fails
				resp.Status.Open = findings.FindingOpen
				resp.Notes["User"] = "Root user does not have an MFA token associated."
			}
		} else {
			// skip to next user if not <root_user> here
			continue
		}
	}
	return resp
}

/*
Check 1.1 avoid use of root accounts
'Avoid' isn't defined, so just check to see if you've used root in last 30 days)
*/
func avoidRootAccountUse(a []accounts.Account) findings.Finding {
	resp := findings.Finding{Name: "Finding 1.1", Description: Finding1_1Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}

	for i := range a {
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {
			if isActiveInDays(a[i]["access_key_1_last_used_date"], days30) ||
				isActiveInDays(a[i]["access_key_2_last_used_date"], days30) ||
				isActiveInDays(a[i]["password_last_used"], days30) {
				// If any of the 3 access methods have been used in the last month, fail the check

				resp.Status.Open = findings.FindingOpen
				resp.Notes["User"] = "Root account or it's access keys used in last 30 days."
			} else {
				// None of the methods have been used in last 30 days, check passes

				resp.Status.Open = findings.FindingClosed
			}
		} else {
			// skip to next user if not <root_user> here
			continue
		}
	}

	return resp
}

func areCredentialsDisabledAfter90Days(a []accounts.Account) findings.Finding {
	overallresp := findings.Finding{Name: "Finding 1.3", Description: Finding1_3Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}
	overallresp.Status.Open = findings.FindingClosed // Default to closed, as absence == pass for this check
	for i := range a {
		var resp = true
		if a[i]["access_key_1_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_1_last_used_date"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
				overallresp.Notes["User"] = fmt.Sprintf("Account %s Access Key 1 unused in 90 days: last used on %s", a[i]["user"], a[i]["access_key_1_last_used_date"])
			}
		}
		if a[i]["access_key_2_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_2_last_used_date"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
				overallresp.Notes["User"] = fmt.Sprintf("Account %s Access Key 2 unused in 90 days: last used on %s", a[i]["user"], a[i]["access_key_2_last_used_date"])
			}
		}
		if a[i]["password_enabled"] == credentialReportTrue {
			if !isActiveInDays(a[i]["password_last_used"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				overallresp.Notes["User"] = fmt.Sprintf("Account %s has password, but unused in 90 days: last used on %s", a[i]["user"], a[i]["password_last_used"])
				resp = false
			}
		}
		if resp == false {
			// If any of the three credential checks fails for this account
			// the entire check fails
			overallresp.Status.Open = findings.FindingOpen
		}
	}
	return overallresp
}

func areCredentialsRotatedWithin90Days(a []accounts.Account) findings.Finding {
	overallresp := findings.Finding{Name: "Finding 1.4", Description: Finding1_4Txt, Status: findings.Status{Checked: true}, Notes: make(map[string]string)}
	overallresp.Status.Open = findings.FindingClosed // Default to closed, as absence == pass for this check
	for i := range a {
		var resp = true
		if a[i]["access_key_1_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_1_last_rotated"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				overallresp.Notes["User"] = fmt.Sprintf("Account %s Access Key 1 active, but older than 90 days: last rotated on %s", a[i]["user"], a[i]["access_key_1_last_rotated"])
				resp = false
			}
		}
		if a[i]["access_key_2_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_2_last_rotated"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				overallresp.Notes["User"] = fmt.Sprintf("Account %s Access Key 2 active, but older than 90 days: last rotated on %s", a[i]["user"], a[i]["access_key_2_last_rotated"])
				resp = false
			}
		}
		if resp == false {
			// If any of the two credential checks fails for this account
			// the entire check fails
			// TODO: figure out how to pass back the name of the account that fails (maybe via log?)
			overallresp.Status.Open = findings.FindingOpen
		}
	}

	return overallresp
}
