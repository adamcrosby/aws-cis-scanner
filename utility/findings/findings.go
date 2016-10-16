package findings

// Status holds the state of a given finding - if it's been checked, and is it Open/Other
type Status struct {
	Checked bool
	Open    string
}

// Finding holds a finding plus it's state at a given moment
type Finding struct {
	Name        string
	Description string
	Status      Status
	Notes       map[string]string
}

// Checks is a mapping of Findings to slugs
type Checks map[string]Finding

// FindingsInCISBenchmark is the number of total findings in the benchmark
const FindingsInCISBenchmark = 43

// FindingOpen indicates a check is 'open' or Failed
const FindingOpen = "Open"

// FindingClosed indicates a check is 'closed' or Passed
const FindingClosed = "Closed"

// FindingUnk indicates a check is in an 'unknown' or untestable state
const FindingUnk = "Unknown"
