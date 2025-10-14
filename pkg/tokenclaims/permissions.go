package tokenclaims

const (
	// PermissionGetNonLocationHistory is the permission to get non-location history.
	PermissionGetNonLocationHistory = "privilege:GetNonLocationHistory"
	// PermissionExecuteCommands is the permission to execute commands on a vehicle.
	PermissionExecuteCommands = "privilege:ExecuteCommands"
	// PermissionGetCurrentLocation is the permission to get the current location of a vehicle.
	// Deprecated: Use PermissionGetLocationHistory instead
	PermissionGetCurrentLocation = "privilege:GetCurrentLocation"
	// PermissionGetLocationHistory is the permission to get the location history of a vehicle.
	PermissionGetLocationHistory = "privilege:GetLocationHistory"
	// PermissionGetVINCredential is the permission to get the VIN credential of a vehicle.
	// This gives access to raw payloads that contain the VIN instead you can limit access to VIN attestations with cloud event agreements.
	PermissionGetVINCredential = "privilege:GetVINCredential"
	// PermissionGetLiveData is the permission to get the live data of a vehicle.
	PermissionGetLiveData = "privilege:GetLiveData"
	// PermissionGetRawData is the permission to get the raw data of a vehicle.
	// This gives access to all the data that is stored on the vehicle instead you can limit what raw data is seen with cloud event agreements.
	PermissionGetRawData = "privilege:GetRawData"
	// PermissionGetApproximateLocation is the permission to get the approximate location of a vehicle.
	PermissionGetApproximateLocation = "privilege:GetApproximateLocation"
)

// PrivilegeIDToName converts the privilege ID to the permission name.
var PrivilegeIDToName = map[int64]string{
	1: PermissionGetNonLocationHistory,  // All-time non-location data
	2: PermissionExecuteCommands,        // Commands
	3: PermissionGetCurrentLocation,     // Current location
	4: PermissionGetLocationHistory,     // All-time location
	5: PermissionGetVINCredential,       // View VIN credential
	6: PermissionGetLiveData,            // Subscribe live data
	7: PermissionGetRawData,             // Raw data
	8: PermissionGetApproximateLocation, // Approximate location
}

// PrivilegeNameToID converts the permission name to the privilege ID.
var PrivilegeNameToID = func() map[string]int64 {
	privMap := make(map[string]int64, len(PrivilegeIDToName))
	for id, name := range PrivilegeIDToName {
		privMap[name] = id
	}
	return privMap
}()
