package benchmark

// Status of the benchmark per finding
type Status struct {
	// Section 1: Identity and access management
	Finding1_1  bool
	Finding1_2  bool
	Finding1_3  bool
	Finding1_4  bool
	Finding1_5  bool
	Finding1_6  bool
	Finding1_7  bool
	Finding1_8  bool
	Finding1_9  bool
	Finding1_10 bool
	Finding1_11 bool
	Finding1_12 bool
	Finding1_13 bool
	Finding1_14 bool
	Finding1_15 bool

	// Section 2: Logging
	Finding2_1 bool
	Finding2_2 bool
	Finding2_3 bool
	Finding2_4 bool
	Finding2_5 bool
	Finding2_6 bool
	Finding2_7 bool
	Finding2_8 bool

	// Section 3: Monitoring
	Finding3_1  bool
	Finding3_2  bool
	Finding3_3  bool
	Finding3_4  bool
	Finding3_5  bool
	Finding3_6  bool
	Finding3_7  bool
	Finding3_8  bool
	Finding3_9  bool
	Finding3_10 bool
	Finding3_11 bool
	Finding3_12 bool
	Finding3_13 bool
	Finding3_14 bool
	Finding3_15 bool
	Finding3_16 bool

	// Section 4: Networking
	Finding4_1 bool
	Finding4_2 bool
	Finding4_3 bool
	Finding4_4 bool
}

// Notes or finding details for each finding (stored as JSON objects)
type Notes struct {
	// Section 1: Identity and access management
	Finding1_1  string `json:"	finding1_1 "`
	Finding1_2  string `json:"	finding1_2 "`
	Finding1_3  string `json:"	finding1_3 "`
	Finding1_4  string `json:"	finding1_4 "`
	Finding1_5  string `json:"	finding1_5 "`
	Finding1_6  string `json:"	finding1_6 "`
	Finding1_7  string `json:"	finding1_7 "`
	Finding1_8  string `json:"	finding1_8 "`
	Finding1_9  string `json:"	finding1_9 "`
	Finding1_10 string `json:"	finding1_10"`
	Finding1_11 string `json:"	finding1_11"`
	Finding1_12 string `json:"	finding1_12"`
	Finding1_13 string `json:"	finding1_13"`
	Finding1_14 string `json:"	finding1_14"`
	Finding1_15 string `json:"	finding1_15"`

	// Section 2: Logging
	Finding2_1 string `json:"	finding2_1"`
	Finding2_2 string `json:"	finding2_2"`
	Finding2_3 string `json:"	finding2_3"`
	Finding2_4 string `json:"	finding2_4"`
	Finding2_5 string `json:"	finding2_5"`
	Finding2_6 string `json:"	finding2_6"`
	Finding2_7 string `json:"	finding2_7"`
	Finding2_8 string `json:"	finding2_8"`

	// Section 3: Monitoring
	Finding3_1  string `json:"	finding3_1 "`
	Finding3_2  string `json:"	finding3_2 "`
	Finding3_3  string `json:"	finding3_3 "`
	Finding3_4  string `json:"	finding3_4 "`
	Finding3_5  string `json:"	finding3_5 "`
	Finding3_6  string `json:"	finding3_6 "`
	Finding3_7  string `json:"	finding3_7 "`
	Finding3_8  string `json:"	finding3_8 "`
	Finding3_9  string `json:"	finding3_9 "`
	Finding3_10 string `json:"	finding3_10"`
	Finding3_11 string `json:"	finding3_11"`
	Finding3_12 string `json:"	finding3_12"`
	Finding3_13 string `json:"	finding3_13"`
	Finding3_14 string `json:"	finding3_14"`
	Finding3_15 string `json:"	finding3_15"`
	Finding3_16 string `json:"	finding3_16"`

	// Section 4: Networking
	Finding4_1 string `json:"	finding4_1"`
	Finding4_2 string `json:"	finding4_2"`
	Finding4_3 string `json:"	finding4_3"`
	Finding4_4 string `json:"	finding4_4"`
}
