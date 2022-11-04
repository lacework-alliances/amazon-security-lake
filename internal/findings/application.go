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

type App struct {
	Event  lacework.LaceworkEvent
	config lacework.Config
}

func (a App) Findings(ctx context.Context) []*ocsf.SecurityFinding {
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

func (a App) enrich(finding ocsf.SecurityFinding, data lacework.Data) {
	var count int
	otherMap := make(map[string]string)
	var id string
	switch data.EventType {
	case "NewExternalClientBadIp", "NewExternalClientConn", "NewExternalServerIp", "NewChildLaunched",
		"NewExternalServerDNSConn", "NewInternalConnection", "NewBinaryType", "NewExternalServerBadDns":
		if len(data.EntityMap.Container) > 0 {
			image := fmt.Sprintf("%s:%s", data.EntityMap.Container[0].IMAGEREPO, data.EntityMap.Container[0].IMAGETAG)
			if len(image) > 64 {
				id = image[:64]
			} else {
				id = image
			}
		} else {
			if len(data.EntityMap.Machine[0].Hostname) > 64 {
				id = data.EntityMap.Machine[0].Hostname[:64]
			} else {
				id = data.EntityMap.Machine[0].Hostname
			}
		}
		if len(data.EntityMap.Container) > 0 {
			containerMap := container(data.EntityMap.Container)
			for k, v := range containerMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}

			}
		}
		if len(data.EntityMap.Machine) > 0 {
			machineMap := machine(data.EntityMap.Machine)
			for k, v := range machineMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.Application) > 0 {
			appMap := application(data.EntityMap.Application)
			for k, v := range appMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.Process) > 0 {
			procMap := process(data.EntityMap.Process)
			for k, v := range procMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.FileExePath) > 0 {
			fileMap := fileExePath(data.EntityMap.FileExePath)
			for k, v := range fileMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.User) > 0 {
			userMap := user(data.EntityMap.User)
			for k, v := range userMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.DnsName) > 0 {
			dnsMap := dns(data.EntityMap.DnsName)
			for k, v := range dnsMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
	case "KnownHostCveDiscovered", "ExistingHostCveSeverityEscalated", "ExistingHostCveFixAvailable":
		var s string
		for _, cve := range data.EntityMap.Cve {
			s = s + " " + cve.CveID
		}
		if len(s) > 64 {
			id = s[:64]
		} else {
			id = s
		}

		cveMap := cve(data.EntityMap.Cve)
		for k, v := range cveMap {
			if count < 50 {
				count++
				otherMap[k] = v
			}
		}
		ruleMap := customRule(data.EntityMap.CustomRule)
		for k, v := range ruleMap {
			if count < 50 {
				count++
				otherMap[k] = v
			}
		}
		featureMap := imageFeature(data.EntityMap.ImageFeature)
		for k, v := range featureMap {
			if count < 50 {
				count++
				otherMap[k] = v
			}
		}
		machineMap := machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			if count < 50 {
				count++
				otherMap[k] = v
			}
		}
	case "NewK8Pod":
		if len(data.EntityMap.K8Pod) > 0 {
			pod := fmt.Sprintf("%s:%s", data.EntityMap.K8Pod[0].NAMESPACE[0], data.EntityMap.K8Pod[0].POD)
			if len(pod) > 64 {
				id = pod[:64]
			} else {
				id = pod
			}
		} else if len(data.EntityMap.K8Namespace) > 0 {
			pod := fmt.Sprintf("%s:%s", data.EntityMap.K8Namespace[0].NAMESPACE, data.EntityMap.K8Namespace[0].POD[0])
			if len(pod) > 64 {
				id = pod[:64]
			} else {
				id = pod
			}
		}
		machineMap := machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			if count < 50 {
				count++
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
		if len(data.EntityMap.Container) > 0 {
			image := fmt.Sprintf("%s:%s", data.EntityMap.Container[0].IMAGEREPO, data.EntityMap.Container[0].IMAGETAG)
			id = image
		} else if len(data.EntityMap.Machine) > 0 {
			id = data.EntityMap.Machine[0].Hostname
		}
		if len(data.EntityMap.Container) > 0 {
			containerMap := container(data.EntityMap.Container)
			for k, v := range containerMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.Machine) > 0 {
			machineMap := machine(data.EntityMap.Machine)
			for k, v := range machineMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.Application) > 0 {
			appMap := application(data.EntityMap.Application)
			for k, v := range appMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.Process) > 0 {
			procMap := process(data.EntityMap.Process)
			for k, v := range procMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.FileExePath) > 0 {
			fileMap := fileExePath(data.EntityMap.FileExePath)
			for k, v := range fileMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.User) > 0 {
			userMap := user(data.EntityMap.User)
			for k, v := range userMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if len(data.EntityMap.DnsName) > 0 {
			dnsMap := dns(data.EntityMap.DnsName)
			for k, v := range dnsMap {
				if count < 50 {
					count++
					otherMap[k] = v
				}
			}
		}
		if a.config.Telemetry {
			honeycomb.SendHoneycombEvent(a.config.Instance, "cloudtrail_event_type_not_found", "", a.config.Version, string(t), "otherDetails", a.config.HoneyDataset, a.config.HoneyKey)
		}
	}
	finding.ResourcesArray = append(finding.ResourcesArray, ocsf.Resource{
		Name: id,
	})
	if json, err := json.Marshal(otherMap); err == nil {
		finding.Data = string(json)
	}
}

func machine(machines []lacework.Machine) map[string]string {
	other := make(map[string]string)
	for i, m := range machines {
		if m.ExternalIP != "" {
			other["MACHINE-EXTERNAL_IP-"+strconv.Itoa(i)] = m.ExternalIP
		}
		if m.InternalIPAddr != "" {
			other["MACHINE-INTERNAL_IP_ADDR-"+strconv.Itoa(i)] = m.InternalIPAddr
		}
		if m.Hostname != "" {
			other["MACHINE-HOSTNAME-"+strconv.Itoa(i)] = m.Hostname
		}
		if m.InstanceID != "" {
			other["MACHINE-INSTANCE_ID-"+strconv.Itoa(i)] = m.InstanceID
		}
	}
	return other
}

func application(apps []lacework.Application) map[string]string {
	other := make(map[string]string)
	for i, app := range apps {
		if app.APPLICATION != "" {
			other["APPLICATION-"+strconv.Itoa(i)] = app.APPLICATION
		}
		if app.EARLIESTKNOWNTIME.String() != "" {
			other["APPLICATION-EARLIEST_KNOWN_TIME-"+strconv.Itoa(i)] = app.EARLIESTKNOWNTIME.String()
		}
	}
	return other
}

func fileExePath(fileExePaths []lacework.FileExePath) map[string]string {
	other := make(map[string]string)
	for i, f := range fileExePaths {
		if f.EXEPATH != "" {
			other["FILE_EXE_PATH-"+strconv.Itoa(i)] = f.EXEPATH
		}
		if f.LASTFILEOWNER != "" {
			other["LAST_FILE_OWNER-"+strconv.Itoa(i)] = f.LASTFILEOWNER
		}
	}
	return other
}

func process(processes []lacework.Process) map[string]string {
	other := make(map[string]string)
	for i, p := range processes {
		if p.HOSTNAME != "" {
			other["PROCESS-HOSTNAME-"+strconv.Itoa(i)] = p.HOSTNAME
		}
		if p.CMDLINE != "" {
			other["PROCESS_CMDLINE-"+strconv.Itoa(i)] = p.CMDLINE
		}
		if p.PROCESSSTARTTIME.String() != "" {
			other["PROCESS_START_TIME-"+strconv.Itoa(i)] = p.PROCESSSTARTTIME.String()
		}
		if p.PROCESSID > 0 {
			other["PROCESS_ID-"+strconv.Itoa(i)] = strconv.Itoa(p.PROCESSID)
		}
		if p.CPUPERCENTAGE >= 0 {
			cpu := fmt.Sprintf("%f", p.CPUPERCENTAGE)
			other["PROCESS-CPU_PERCENTAGE-"+strconv.Itoa(i)] = cpu
		}
	}
	return other
}

func user(users []lacework.User) map[string]string {
	other := make(map[string]string)
	for i, u := range users {
		if u.MACHINEHOSTNAME != "" {
			other["USER-MACHINE_HOSTNAME-"+strconv.Itoa(i)] = u.MACHINEHOSTNAME
		}
		if u.USERNAME != "" {
			other["USER-MACHINE-USERNAME-"+strconv.Itoa(i)] = u.USERNAME
		}
	}
	return other
}

func ipAddress(ips []lacework.IpAddress) map[string]string {
	other := make(map[string]string)
	for i, p := range ips {
		if p.Region != "" {
			other["IP-REGION-"+strconv.Itoa(i)] = p.Region
		}
		if p.IPAddress != "" {
			other["IP_ADDRESS-"+strconv.Itoa(i)] = p.IPAddress
		}
		if p.ThreatTags != "" {
			other["IP-THREAT-TAGS-"+strconv.Itoa(i)] = p.ThreatTags
		}
		if p.Country != "" {
			other["IP-COUNTRY-"+strconv.Itoa(i)] = p.Country
		}
		if p.TotalOutBytes != 0 {
			other["IP-TOTAL-OUT-BYTES-"+strconv.Itoa(i)] = strconv.Itoa(p.TotalOutBytes)
		}
		if p.TotalInBytes != 0 {
			other["IP-TOTAL-IN-BYTES-"+strconv.Itoa(i)] = strconv.Itoa(p.TotalInBytes)
		}
		if len(p.PortList) > 0 {
			var ports string
			for _, port := range p.PortList {
				ports = ports + " " + strconv.Itoa(port)
			}
			other["PORT-LIST-"+strconv.Itoa(i)] = ports
		}
		if len(p.ThreatSource) > 0 {
			for j, threat := range p.ThreatSource {
				other["THREAT-SOURCE-DATE-"+strconv.Itoa(j)] = threat.Date
				other["THREAT-SOURCE-TAG-"+strconv.Itoa(i)] = threat.PrimaryThreatTag
				other["THREAT-SOURCE-"+strconv.Itoa(i)] = threat.Source
			}
		}
	}
	return other
}

func dns(dns []lacework.DnsName) map[string]string {
	other := make(map[string]string)
	for i, p := range dns {
		if p.HOSTNAME != "" {
			other["DNS-HOSTNAME-"+strconv.Itoa(i)] = p.HOSTNAME
		}
		out := fmt.Sprintf("%f", p.TOTALOUTBYTES)
		in := fmt.Sprintf("%f", p.TOTALINBYTES)
		other["DNS-TOTAL_OUT_BYTES-"+strconv.Itoa(i)] = out
		other["DNS-TOTAL_IN_BYTES-"+strconv.Itoa(i)] = in
		if len(p.PORTLIST) > 0 {
			var ports string
			for _, port := range p.PORTLIST {
				ports = ports + " " + strconv.Itoa(port)
			}
			other["PORT_LIST-"+strconv.Itoa(i)] = ports
		}
	}
	return other
}

func imageId(images []lacework.Imageid) map[string]string {
	other := make(map[string]string)
	img := fmt.Sprintf("%s:%s", images[0].ImageRepo, images[0].ImageID)
	other["IMAGE"] = img
	other["IMAGE_ACTIVE"] = isActive(images[0].ImageActive)
	for i, tag := range images[0].ImageTag {
		other["TAG-"+strconv.Itoa(i)] = tag

	}
	return other
}

func imageFeature(features []lacework.ImageFeature) map[string]string {
	other := make(map[string]string)
	for _, f := range features {
		if f.FeatureName != "" {
			other["FEATURE_NAME"] = f.FeatureName
		}
		if f.FeatureNamespace != "" {
			other["FEATURE_NAMESPACE"] = f.FeatureNamespace
		}
		for i, cve := range f.Cve {
			other[f.FeatureName+"-CVE-"+strconv.Itoa(i)] = cve
		}
		if f.FixedVersion != "" {
			other["FEATURE-FIXED-VERSION"] = f.FixedVersion
		}
	}
	return other
}

func customRule(cr []lacework.CustomRule) map[string]string {
	other := make(map[string]string)
	for i, r := range cr {
		if r.RuleGUID != "" {
			other["RULE_GUID-"+strconv.Itoa(i)] = r.RuleGUID
		}
		if r.LastUpdatedUser != "" {
			other["LAST_UPDATED_USER-"+strconv.Itoa(i)] = r.LastUpdatedUser
		}
		if r.LastUpdatedTime.String() != "" {
			other["LAST_UPDATED_TIME-"+strconv.Itoa(i)] = r.LastUpdatedTime.String()
		}
		if r.DisplayFilter != "" {
			other["DISPLAY_FILTER-"+strconv.Itoa(i)] = r.DisplayFilter
		}
	}
	return other
}

func cve(cves []lacework.Cve) map[string]string {
	other := make(map[string]string)
	for _, c := range cves {
		if c.FeatureName != "" {
			other[c.CveID+"-FEATURE_NAME"] = c.FeatureName
			other[c.CveID+"-INFO"] = c.Info
			other[c.CveID+"-SEVERITY"] = string(c.Severity)
		}
	}
	return other
}

func container(containers []lacework.Container) map[string]string {
	other := make(map[string]string)
	public := "no"
	client := "no"
	server := "no"
	for i, c := range containers {
		if c.HASEXTERNALCONNS == 1 {
			public = "yes"
		}
		other["CONTAINER-PUBLIC-"+strconv.Itoa(i)] = public
		if c.ISCLIENT == 1 {
			client = "yes"
		}
		other["CONTAINER-CLIENT-"+strconv.Itoa(i)] = client
		if c.ISSERVER == 1 {
			server = "yes"
		}
		other["CONTAINER-SERVER-"+strconv.Itoa(i)] = server
		if c.FIRSTSEENTIME != "" {
			other["CONTAINER-FIRST-SEEN-"+strconv.Itoa(i)] = c.FIRSTSEENTIME
		}
		if c.CLUSTERNAME != "" {
			other["CONTAINER-CLUSTER-"+strconv.Itoa(i)] = c.CLUSTERNAME
		}
		img := fmt.Sprintf("%s:%s", c.IMAGEREPO, c.IMAGETAG)
		other["CONTAINER-IMAGE-"+strconv.Itoa(i)] = img
	}
	return other
}
