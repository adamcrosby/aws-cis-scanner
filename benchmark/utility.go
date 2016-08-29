package benchmark

import "time"

func isActiveInLastDay(t1 *time.Time) bool {
	var resp bool
	hours := time.Since(*t1).Hours()
	// if last time we used the  account was less than a month ago
	if hours < days1 {
		// account has been used in 30 days
		resp = true
	} else {
		resp = false
	}
	return resp
}

/*
Helper function to check if the last date something was used was within <duration> days
*/
func isActiveInDays(timeString string, duration float64) bool {
	var resp bool
	t1, _ := time.Parse(time.RFC3339, timeString)
	hours := time.Since(t1).Hours()
	// if last time we used the  account was less than a month ago

	if hours < duration {
		// account has been used in 30 days
		resp = true
	} else {
		resp = false
	}
	return resp
}
