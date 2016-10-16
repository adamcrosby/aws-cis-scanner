package regions

const (
	// APNorthEast1 is the Tokyo region
	APNorthEast1 = "ap-northeast-1"
	// APNorthEast2 is the Seoul region
	APNorthEast2 = "ap-northeast-2"
	//APSouth1     is the  Mumbai region
	APSouth1 = "ap-south-1"
	//APSouthEast1 is the  Singapore region
	APSouthEast1 = "ap-southeast-1"
	//APSouthEast2 is the  Sydney region
	APSouthEast2 = "ap-southeast-2"
	//CNNorth1     is the  Beijing region
	CNNorth1 = "cn-north-1"
	//EUCentral1   is the  Frankfurt region
	EUCentral1 = "eu-central-1"
	//EUWest1      is the  Ireland region
	EUWest1 = "eu-west-1"
	//GovCloud is the US GovCloud (Oregon) region
	GovCloud = "us-gov-west-1"
	//SAEast1 is the Sao  Paulo region
	SAEast1 = "sa-east-1"
	//USEast1  is the N. Virginia region
	USEast1 = "us-east-1"
	//USWest1 is the N. California region
	USWest1 = "us-west-1"
	//USWest2 is the Oregon
	USWest2 = "us-west-2"
)

// CommercialRegions is an array of region IDs for iteration for non-govcloud, non-CN region usage
//var CommercialRegions = []string{APNorthEast1, APNorthEast2, APSouth1, APSouthEast1, APSouthEast2, EUCentral1, EUWest1, SAEast1, USEast1, USWest1, USWest2}
var CommercialRegions = []string{USEast1}

// GovRegions is an array of region IDs for iteration for GovCloud usage
var GovRegions = []string{GovCloud}

// CNRegions is an array of region IDs for iteration for CN Region usage
var CNRegions = []string{CNNorth1}
