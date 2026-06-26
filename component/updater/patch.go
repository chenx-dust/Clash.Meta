package updater

var (
	GeoUpdateHook func(geoType string, updating bool, updateErr error)
)

func sendGeoUpdateStatus(geoType string, updating bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, updateErr)
	}
}
