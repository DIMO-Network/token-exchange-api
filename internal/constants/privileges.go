package privilegemap

// privilege prefix to denote the 1:1 mapping to bit values and to make them easier to deprecate if desired in the future
var PrivilegeIDToName = map[int64]string{
	1: "privilege:GetNonLocationHistory",  // All-time non-location data
	2: "privilege:ExecuteCommands",        // Commands
	3: "privilege:GetCurrentLocation",     // Current location
	4: "privilege:GetLocationHistory",     // All-time location
	5: "privilege:GetVINCredential",       // View VIN credential
	6: "privilege:GetLiveData",            // Subscribe live data
	7: "privilege:GetRawData",             // Raw data
	8: "privilege:GetApproximateLocation", // Approximate location
}

// PrivilegeNameToID is the reverse mapping
var PrivilegeNameToID = func() map[string]int64 {
	privMap := make(map[string]int64, len(PrivilegeIDToName))
	for id, name := range PrivilegeIDToName {
		privMap[name] = id
	}
	return privMap
}()
