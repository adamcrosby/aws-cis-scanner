package regions

type ServiceParams struct {
	useCommercialRegions bool
	commercialEndpoint   string
	useUSGovCloudRegion  bool
	usGovCloudEndpoint   string
	useCNRegion          bool
	cnRegionEndpoint     string
	useC2SRegion         bool
	c2SRegionEndpoint    string
}

const CommercialEndpointDefault = "us-east-1"
const USGovCloudEndpointDefault = "us-gov-west-1"
