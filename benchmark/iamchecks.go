package benchmark

import (
	"github.com/adamcrosby/aws-cis-scanner/utility/accounts"
	"github.com/aws/aws-sdk-go/service/iam"
)

// Findings dictionary to hold findings
type Findings map[string]bool

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
func DoIAMChecks(s Status, a []accounts.Account, pp iam.PasswordPolicy) Status {
	s = ratePasswordPolicy(pp, s)
	s.Finding1_1 = avoidRootAccountUse(a)
	s.Finding1_2 = iamMFAEnabled(a)
	s.Finding1_3 = areCredentialsDisabledAfter90Days(a)
	s.Finding1_4 = areCredentialsRotatedWithin90Days(a)
	s.Finding1_12 = ensureNoRootAccessKey(a)
	s.Finding1_13 = ensureRootAccountMFAEnabled(a)

	return s
}

/*
Check 1.5 - # of upper case characters
*/
func passPolicyUpperCase(pp iam.PasswordPolicy) bool {
	if *pp.RequireUppercaseCharacters {
		return true
	}
	return false

}

/*
Check 1.6 - # of lower case characters
*/
func passPolicyLowerCase(pp iam.PasswordPolicy) bool {
	if *pp.RequireLowercaseCharacters {
		return true
	}
	return false
}

/*
Check 1.7 - # of symbol characters
*/
func passPolicySymbol(pp iam.PasswordPolicy) bool {
	if *pp.RequireSymbols {
		return true
	}
	return false
}

/*
Check 1.8 - # of digit/number characters
*/
func passPolicyNumber(pp iam.PasswordPolicy) bool {
	if *pp.RequireNumbers {
		return true
	}
	return false
}

/*
Check 1.9 - minimum password length
*/
func passPolicyMinLength(pp iam.PasswordPolicy) bool {
	if *pp.MinimumPasswordLength >= finding1_9Val {
		return true
	}
	return false
}

/*
Check 1.10 - password reuse prevention
*/
func passPolicyPreventReuse(pp iam.PasswordPolicy) bool {
	if pp.PasswordReusePrevention != nil {
		if *pp.PasswordReusePrevention != 0 {
			return true
		}

	}
	return false
}

/*
Check 1.11 - max password age
*/
func passPolicyMaxAge(pp iam.PasswordPolicy) bool {
	if *pp.ExpirePasswords && (*pp.MaxPasswordAge > finding1_11Val) {
		return true
	}
	return false
}

/*
RatePasswordPolicy calls the individual functions to figure out status
*/
func ratePasswordPolicy(pp iam.PasswordPolicy, findings Status) Status {

	if pp != (iam.PasswordPolicy{}) {
		findings.Finding1_5 = passPolicyUpperCase(pp)
		findings.Finding1_6 = passPolicyLowerCase(pp)
		findings.Finding1_7 = passPolicySymbol(pp)
		findings.Finding1_8 = passPolicyNumber(pp)
		findings.Finding1_9 = passPolicyMinLength(pp)
		findings.Finding1_10 = passPolicyPreventReuse(pp)
		findings.Finding1_11 = passPolicyMaxAge(pp)
	} else {
		findings.Finding1_5 = false
		findings.Finding1_6 = false
		findings.Finding1_7 = false
		findings.Finding1_8 = false
		findings.Finding1_9 = false
		findings.Finding1_10 = false
		findings.Finding1_11 = false
	}

	return findings
}

/*
Check 1.2 - Ensure MFA is enabled for all iam users with passwords
*/
func iamMFAEnabled(a []accounts.Account) bool {
	// Iterate over each account in the list
	var resp bool
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
				resp = false
			} else {
				//fmt.Printf("User: %s has no password, or has password and MFA\n", a[i]["user"])
				resp = true
			}
		}

	}
	return resp
}

/*
Check 1.12 - ensure no root access key exists
*/
func ensureNoRootAccessKey(a []accounts.Account) bool {
	// Iterate over each account in the list
	var resp bool
	for i := range a {
		//fmt.Printf("Processing username: %s\n", a[i]["user"])
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {
			//fmt.Println("Root account, chekcing")
			if a[i]["access_key_1_active"] == credentialReportTrue || a[i]["access_key_2_active"] == credentialReportTrue {
				//fmt.Println("Root account has an active access key")
				// resp is false because this check FAILS if either of these conditions are true
				resp = false
			} else {
				// Root does not have an active access key
				//fmt.Println("Root account does not have an active access key")
				resp = true
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
func ensureRootAccountMFAEnabled(a []accounts.Account) bool {
	// Iterate over each account in the list
	var resp bool
	for i := range a {
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {
			//fmt.Println("Root account, chekcing")
			if a[i]["mfa_active"] == credentialReportTrue {
				// // Root has an MFA token, check passes
				resp = true
			} else {
				// Root does not have an MFA token, check fails
				resp = false
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
We use a heuristic (not really, we just see if you've used root in last 30 days)
*/
func avoidRootAccountUse(a []accounts.Account) bool {
	var resp bool
	for i := range a {
		// only check <root_user> here
		if a[i]["user"] == rootAccountName {
			if isActiveInDays(a[i]["access_key_1_last_used_date"], days30) ||
				isActiveInDays(a[i]["access_key_2_last_used_date"], days30) ||
				isActiveInDays(a[i]["password_last_used"], days30) {
				// If any of the 3 access methods have been used in the last month, fail the check

				resp = false
			} else {
				// None of the methods have been used in last 30 days, check passes

				resp = true
			}
		} else {
			// skip to next user if not <root_user> here
			continue
		}
	}
	return resp
}

func areCredentialsDisabledAfter90Days(a []accounts.Account) bool {
	var overallresp = true
	for i := range a {
		var resp = true
		if a[i]["access_key_1_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_1_last_used_date"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
			}
		}
		if a[i]["access_key_2_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_2_last_used_date"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
			}
		}
		if a[i]["password_enabled"] == credentialReportTrue {
			if !isActiveInDays(a[i]["password_last_used"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
			}
		}
		if resp == false {
			// If any of the three credential checks fails for this account
			// the entire check fails
			// TODO: figure out how to pass back the name of the account that fails (maybe via log?)
			overallresp = false
		}
	}
	return overallresp
}

func areCredentialsRotatedWithin90Days(a []accounts.Account) bool {
	var overallresp = true
	for i := range a {
		var resp = true
		if a[i]["access_key_1_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_1_last_rotated"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
			}
		}
		if a[i]["access_key_2_active"] == credentialReportTrue {
			if !isActiveInDays(a[i]["access_key_2_last_rotated"], days90) {
				// credential hasn't been used within 90  days but is enabled
				// so fail the check
				resp = false
			}
		}
		if resp == false {
			// If any of the two credential checks fails for this account
			// the entire check fails
			// TODO: figure out how to pass back the name of the account that fails (maybe via log?)
			overallresp = false
		}
	}

	return overallresp
}
