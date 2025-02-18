package findings

import "github.com/lacework-alliances/amazon-security-lake/pkg/ocsf"

// InitMap initializes maps based on the event type to an AWS Finding Type
func InitMap() map[string][]int {
	// map[EVENT_TYPE][CATEGORY,CLASS]
	var eventMap = map[string][]int{}

	eventMap["PotentiallyCompromisedAwsCredentials"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}
	eventMap["PotentiallyCompromisedHost"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}
	eventMap["PotentiallyCompromisedAzure"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}
	eventMap["PotentiallyCompromisedGCP"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}
	eventMap["PotentiallyCompromisedK8s"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}
	eventMap["PotentialPenetrationTest"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDDetectionFinding}


	eventMap["NewExternalServerDns"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalServerIp"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalDnsServer"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalServerDNSConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalServerIPConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalServerBadDns"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalServerBadIp"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalServerBadIPConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalServerBadDNSConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalBadDnsServer"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalClientIp"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalClientDns"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewExternalClientConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalClientBadIpConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalClientBadIp"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewExternalClientBadDns"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewInternalServerIP"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewInternalClientIP"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewInternalConnection"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewErrorDns"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewDnsQueryToCountry"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDDnsActivity}
	eventMap["NewBinaryType"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["NewMachineServerCluster"] = []int{ocsf.CategoryUIDVirtualizationActivity, ocsf.ClassUIDVirtualMachineActivity}
	eventMap["NewUser"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["NewPrivilegeEscalation"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["NewChildLaunched"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["MachineClusterLaunchedNewBinary"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["UserLaunchedNewBinary"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["UserLoggedInFromNewIp"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["UserLoggedInFromNewLocation"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}

	eventMap["NewK8Cluster"] = []int{ocsf.CategoryUIDVirtualizationActivity, ocsf.ClassUIDVirtualMachineActivity}
	eventMap["NewK8Namespace"] = []int{ocsf.CategoryUIDVirtualizationActivity, ocsf.ClassUIDContainerLifecycle}
	eventMap["NewK8Pod"] = []int{ocsf.CategoryUIDVirtualizationActivity, ocsf.ClassUIDContainerLifecycle}

	eventMap["NewAccount"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["AwsUserLoggedInFromSource"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["UserCalltypeMfa"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["NewService"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["UserUsedServiceInRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewErrorCode"] = []int{ocsf.CategoryUIDApplicationActivity, ocsf.ClassUIDAccessActivity}
	eventMap["LoginFromBadSourceUsingCalltype"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["LoginFromSourceUsingCalltype"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["UserAccessingRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["ServiceAccessedInRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["ServiceCalledApi"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["ApiFailedWithError"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}

	eventMap["SuspiciousLogin"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["BadIpServerConn"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["MaliciousFile"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDFileSystemActivity}

	eventMap["NewVPC"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["VPCChange"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["SecurityGroupChange"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NACLChange"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewVPNConnection"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["VPNGatewayChange"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NetworkGatewayChange"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["RouteTableChange"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NewS3Bucket"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudStorage}
	eventMap["S3BucketDeleted"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudStorage}
	eventMap["S3BucketPolicyChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudStorage}
	eventMap["S3BucketACLChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudStorage}
	eventMap["IAMAccessKeyChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["IAMPolicyChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewAccessKey"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["AccessKeyDeleted"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["CloudTrailChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["CloudTrailStopped"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["CloudTrailDeleted"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewCustomerMasterKey"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["NewCustomerMasterKeyAlias"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["CustomerMasterKeyDisabled"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["NewGrantAddedToCustomerMasterKey"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["CustomerMasterKeyScheduledForDeletion"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["SuccessfulConsoleLoginWithoutMFA"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["FailedConsoleLogin"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["UsageOfRootAccount"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["UnauthorizedAPICall"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["ConfigServiceChange"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["CloudTrailDefaultAlert"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}

	eventMap["ComplianceChanged"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDComplianceFinding}
	eventMap["NewViolations"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDComplianceFinding}

	eventMap["SuspiciousApplicationLaunched"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["SuspiciousUserLoginMultiGEOs"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["SuspiciousUserFailedLogin"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["ChangedFile"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDFileSystemActivity}
	eventMap["DeletedFile"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDFileSystemActivity}
	eventMap["NewFile"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDFileSystemActivity}
	eventMap["SuspiciousFile"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDFileSystemActivity}

	eventMap["NewCveDiscovered"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingCveNewInDatacenter"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingCveNewInRepo"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingCveSeverityEscalated"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingCveFixAvailable"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}

	eventMap["NewHostCveDiscovered"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["KnownHostCveDiscovered"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingHostCveSeverityEscalated"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}
	eventMap["ExistingHostCveFixAvailable"] = []int{ocsf.CategoryUIDFindings, ocsf.ClassUIDVulnerabilityFinding}

	eventMap["PolicyAssignmentCreated"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["NetworkSecurityGroupCreatedOrUpdated"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NetworkSecurityGroupDeleted"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NetworkSecurityGroupRuleCreatedOrUpdated"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["NetworkSecurityGroupRuleDeleted"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["SecuritySolutionCreatedOrUpdated"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["SecuritySolutionDeleted"] = []int{ocsf.CategoryUIDSystemActivity, ocsf.ClassUIDProcessActivity}
	eventMap["SQLServerFirewallRuleCreatedOrUpdated"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["SQLServerFirewallRuleDeleted"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["SecurityPolicyUpdated"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}

	eventMap["ProjectOwnershipAssignmentsChanged"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["AuditConfigurationChanged"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["CustomRoleChanged"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["VPCNetworkFirewallRuleChanged"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["VPCNetworkRouteChanged"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["VPCNetworkChanged"] = []int{ocsf.CategoryUIDNetworkActivity, ocsf.ClassUIDNetworkActivity}
	eventMap["CloudStorageIAMPermissionChanged"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudStorage}
	eventMap["SQLInstanceConfigurationChanged"] = []int{ocsf.CategoryUIDDatabaseActivity, ocsf.ClassUIDDatabaseLifecycle}

	eventMap["NewPolicyViolation"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}
	eventMap["PolicyViolationChanged"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthorization}

	eventMap["CloudActivityLogIngestionFailed"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}

	eventMap["NewOrganization"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewGcpSource"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewGcpUser"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAccountChange}
	eventMap["NewGcpRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewGcpService"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewGcpApiCall"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["GcpUserLoggedInFromSource"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["GcpUserLoggedInFromBadSource"] = []int{ocsf.CategoryUIDAuditActivity, ocsf.ClassUIDAuthentication}
	eventMap["GcpUserAccessingRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["GcpServiceAccessedInRegion"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["ServiceCalledGcpApi"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["GcpApiFailedWithError"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}

	eventMap["NewK8sAuditLogClusterRole"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogClusterRoleBinding"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogRole"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogRoleBinding"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogNamespace"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogWorkload"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogImageRepository"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogUser"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}
	eventMap["NewK8sAuditLogIngress"] = []int{ocsf.CategoryUIDCloudActivity, ocsf.ClassUIDCloudApi}

	return eventMap
}
