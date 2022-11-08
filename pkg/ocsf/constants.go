package ocsf

type SeverityID int

const (
	SeverityIDOther         = -1
	SeverityIDUnknown       = 0
	SeverityIDInformational = 1
	SeverityIDLow           = 2
	SeverityIDMedium        = 3
	SeverityIDHigh          = 4
	SeverityIDCritical      = 5
	SeverityIDFatal         = 6
)

type ActivityID int

const (
	ActivityIDOther    = -1
	ActivityIDUnknown  = 0
	ActivityIDGenerate = 1
	ActivityIDUpdate   = 2
)

type CategoryUID int

const (
	CategoryUIDOther                  = -1
	CategoryUIDUnknown                = 0
	CategoryUIDSystemActivity         = 1
	CategoryUIDFindings               = 2
	CategoryUIDAuditActivity          = 3
	CategoryUIDNetworkActivity        = 4
	CategoryUIDCloudActivity          = 5
	CategoryUIDVirtualizationActivity = 6
	CategoryUIDDatabaseActivity       = 7
	CategoryUIDApplicationActivity    = 8
	CategoryUIDConfigurationInventory = 9
)

type ClassUID int

const (
	ClassUIDFileSystemActivity     = 1000
	ClassUIDKernelActivity         = 1003
	ClassUIDMemoryActivity         = 1004
	ClassUIDModuleActivity         = 1005
	ClassUIDProcessActivity        = 1007
	ClassUIDRegistryKeyActivity    = 1008
	ClassUIDRegistryValueActivity  = 1009
	ClassUIDResourceActivity       = 1010
	ClassUIDScheduledJobActivity   = 1011
	ClassUIDKernelExtension        = 1013
	ClassUIDSecurityFinding        = 2001
	ClassUIDAccountChange          = 3001
	ClassUIDAuthentication         = 3002
	ClassUIDAuthorization          = 3003
	ClassUIDEntityManagementAudit  = 3004
	ClassUIDNetworkActivity        = 4001
	ClassUIDHttpActivity           = 4002
	ClassUIDDnsActivity            = 4003
	ClassUIDDhcpActivity           = 4004
	ClassUIDRdpActivity            = 4005
	ClassUIDSmbActivity            = 4006
	ClassUIDSshActivity            = 4007
	ClassUIDFtpActivity            = 4008
	ClassUIDRfbActivity            = 4009
	ClassUIDSmtpActivity           = 4010
	ClassUIDCloudApi               = 5001
	ClassUIDCloudStorage           = 5002
	ClassUIDContainerLifecycle     = 6001
	ClassUIDVirtualMachineActivity = 6002
	ClassUIDDatabaseLifecycle      = 7000
	ClassUIDAccessActivity         = 8001
	ClassUIDInventoryInfo          = 9001
	ClassUIDConfigState            = 9002
)

type StateID int

const (
	StateIDOther      = -1
	StateIDUnknown    = 0
	StateIDNew        = 1
	StateIDInProgress = 2
	StateIDSuppressed = 3
	StateIDResolved   = 4
)

type TypeUID int

const (
	TypeUIDOther    = -1
	TypeUIDUnknown  = 200100
	TypeUIDGenerate = 200101
	TypeUIDUpdate   = 200102
)
