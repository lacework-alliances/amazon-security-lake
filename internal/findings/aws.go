package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lacework-alliances/aws-moose-integration/internal/honeycomb"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"github.com/lacework-alliances/aws-moose-integration/pkg/ocsf"
	"strconv"
)

type Aws struct {
	Event  lacework.LaceworkEvent
	config lacework.Config
}

func (a Aws) Findings(ctx context.Context) []*ocsf.SecurityFinding {
	var fs []*ocsf.SecurityFinding
	// grab the config struct from the context
	a.config = ctx.Value("config").(lacework.Config)
	for _, data := range a.Event.Detail.EventDetails.Data {
		finding := mapDefault(ctx, a.Event)
		a.enrich(finding, data)
		fs = append(fs, &finding)
	}
	return fs
}

func (a Aws) enrich(finding ocsf.SecurityFinding, data lacework.Data) {
	otherMap := make(map[string]string)
	var id string
	// Check the EVENT_TYPE and make decisions

	switch data.EventType {
	case "UserUsedServiceInRegion", "ServiceAccessedInRegion", "NewService", "NewCustomerMasterKey", "CustomerMasterKeyScheduledForDeletion",
		"UsageOfRootAccount", "FailedConsoleLogin", "CLoudTrailDefaultAlert":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = data.EntityMap.CtUser[0].Username[:64]
		} else {
			id = data.EntityMap.CtUser[0].Username
		}

		ipMap := a.ipAddress(data.EntityMap.SourceIpAddress)
		for k, v := range ipMap {
			otherMap[k] = v
		}
		apiMap := a.API(data.EntityMap.API)
		for k, v := range apiMap {
			otherMap[k] = v
		}
	case "UnauthorizedAPICall", "IAMPolicyChanged", "NetworkGatewayChange", "RouteTableChange", "SecurityGroupChange":
		rule := fmt.Sprintf("%s(s)-%s", data.EntityMap.RulesTriggered[0].RuleTitle, data.EntityMap.RulesTriggered[0].RuleID)
		if len(rule) > 64 {
			id = rule[:64]
		} else {
			id = rule
		}

		ruleMap := a.rule(data.EntityMap.RulesTriggered)
		for k, v := range ruleMap {
			otherMap[k] = v
		}
	case "SuccessfulConsoleLoginWithoutMFA", "ServiceCalledApi", "S3BucketPolicyChanged", "S3BucketACLChanged",
		"LoginFromSourceUsingCalltype", "ApiFailedWithError", "AwsAccountFailedApi", "NewCustomerMasterKeyAlias",
		"NewGrantAddedToCustomerMasterKey":
		rule := fmt.Sprintf("%s-%s", data.EntityMap.CtUser[0].PrincipalID, data.EntityMap.CtUser[0].Username)
		if len(rule) > 64 {
			id = rule[:64]
		} else {
			id = rule
		}
		ctUserMap := a.ctUser(data.EntityMap.CtUser)
		for k, v := range ctUserMap {
			otherMap[k] = v
		}
	case "NewUser", "VPCChange":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = data.EntityMap.CtUser[0].Username[:64]
		} else {
			id = data.EntityMap.CtUser[0].Username
		}

	case "IAMAccessKeyChanged":
		if len(data.EntityMap.CtUser[0].PrincipalID) > 64 {
			id = data.EntityMap.CtUser[0].PrincipalID[:64]
		} else {
			id = data.EntityMap.CtUser[0].PrincipalID
		}
	case "NewRegion", "NewVPC":
		if len(data.EntityMap.Region[0].Region) > 64 {
			id = data.EntityMap.Region[0].Region[:64]
		} else {
			id = data.EntityMap.Region[0].Region
		}

	case "NewS3Bucket", "S3BucketDeleted":
		for _, resource := range data.EntityMap.Resource {
			if resource.Name == "bucketName" {
				if len(resource.Value) > 64 {
					id = resource.Value[:64]
				} else {
					id = resource.Value
				}
			}
		}
	case "CloudTrailChanged", "CloudTrailDeleted":
		for _, resource := range data.EntityMap.Resource {
			if resource.Name == "name" {
				if len(resource.Value) > 64 {
					id = resource.Value[:64]
				} else {
					id = resource.Value
				}
			}
		}
	case "CloudTrailDefaultAlert":
		if len(data.EntityMap.CtUser) > 0 {
			if len(data.EntityMap.CtUser[0].PrincipalID) > 64 {
				id = data.EntityMap.CtUser[0].PrincipalID[:64]
			} else {
				id = data.EntityMap.CtUser[0].PrincipalID
			}
			ctUserMap := a.ctUser(data.EntityMap.CtUser)
			for k, v := range ctUserMap {
				otherMap[k] = v
			}
		}
	default:
		d := fmt.Sprintf("%s-%s", data.EventModel, data.EventType)
		if len(d) > 64 {
			id = d[:64]
		} else {
			id = d
		}

		fmt.Printf("EventType has no rule: %s\n", data.EventType)
		t, _ := json.Marshal(data)
		if a.config.Telemetry {
			honeycomb.SendHoneycombEvent(a.config.Instance, "cloudtrail_event_type_not_found", "", a.config.Version, string(t), "otherDetails")
		}
	}
	finding.ResourcesArray = append(finding.ResourcesArray, ocsf.Resource{
		Name: id,
	})
	if json, err := json.Marshal(otherMap); err == nil {
		finding.Data = string(json)
	}
}

func (a Aws) rule(rules []lacework.Rule) map[string]string {
	other := make(map[string]string)
	for i, p := range rules {
		if p.RuleTitle != "" {
			other["RULE_TITLE-"+strconv.Itoa(i)] = p.RuleTitle
		}
		if p.RuleID != "" {
			other["RULE_ID-"+strconv.Itoa(i)] = p.RuleID
		}
		if p.RuleDescription != "" {
			other["RULE_DESCRIPTION-"+strconv.Itoa(i)] = p.RuleDescription
		}
	}
	return other
}

func (a Aws) ctUser(ctUsers []lacework.CtUser) map[string]string {
	other := make(map[string]string)
	for i, p := range ctUsers {
		if p.Username != "" {
			other["CT_USER-"+strconv.Itoa(i)] = p.Username
		}
		if p.AccountID != "" {
			other["ACCOUNT_ID-"+strconv.Itoa(i)] = p.AccountID
		}
		if p.PrincipalID != "" {
			other["PRINCIPAL_ID-"+strconv.Itoa(i)] = p.PrincipalID
		}
	}
	return other
}

func (a Aws) ipAddress(ips []lacework.SourceIpAddress) map[string]string {
	other := make(map[string]string)
	for i, p := range ips {
		if p.Region != "" {
			other["IP-REGION-"+strconv.Itoa(i)] = p.Region
		}
		if p.IPAddress != "" {
			other["IP_ADDRESS-"+strconv.Itoa(i)] = p.IPAddress
		}
		if p.Country != "" {
			other["IP-COUNTRY-"+strconv.Itoa(i)] = p.Country
		}
	}
	return other
}

func (a Aws) API(apis []lacework.API) map[string]string {
	other := make(map[string]string)
	for i, p := range apis {
		if p.Service != "" {
			other["API-SERVICE-"+strconv.Itoa(i)] = p.Service
		}
	}
	return other
}
