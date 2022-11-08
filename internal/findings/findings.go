package findings

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"github.com/lacework-alliances/aws-moose-integration/pkg/ocsf"
	"regexp"
	"strings"
)

const (
	VERSION = "1.0.0"
)

func EventToOCSF(ctx context.Context, le lacework.LaceworkEvent) []ocsf.SecurityFinding {
	var fs []ocsf.SecurityFinding
	var category string
	// get the category to determine finding
	category = le.Detail.EventCategory
	cfg := ctx.Value("config").(lacework.Config)
	switch category {
	case "App":
		fmt.Println("source is App")
		app := App{Event: le, config: cfg}
		findings := app.Findings(ctx)
		fs = append(fs, findings...)
	case "Compliance":
		fmt.Println("source is Compliance")
		comp := Compliance{Event: le, config: cfg}
		findings := comp.Findings(ctx)
		fs = append(fs, findings...)
	case "Aws":
		fmt.Println("source is AWS")
		a := Aws{Event: le, config: cfg}
		findings := a.Findings(ctx)
		fs = append(fs, findings...)
	case "GcpAuditTrail":
		finding := mapDefault(ctx, le)
		fs = append(fs, finding)
	case "User":
		finding := mapDefault(ctx, le)
		fs = append(fs, finding)
	case "TestEvent":
		return fs
	default:
		fmt.Printf("Unknown category: %s\n", category)
		finding := mapDefault(ctx, le)
		fs = append(fs, finding)
	}

	return fs
}

func mapDefault(ctx context.Context, le lacework.LaceworkEvent) ocsf.SecurityFinding {
	var desc string
	if len(le.Detail.Summary) >= 255 {
		desc = le.Detail.Summary[:255]
	} else {
		desc = le.Detail.Summary
	}
	finding := ocsf.SecurityFinding{
		ActivityID:  ocsf.ActivityIDGenerate,
		Category:    "Findings",
		CategoryUID: ocsf.CategoryUIDFindings,
		Class:       "Security Finding",
		ClassUID:    ocsf.ClassUIDSecurityFinding,
		EventTime:   le.Time.Unix(),
		Finding: ocsf.FindingDetails{
			CreatedTime: le.Time.Unix(),
			Description: le.Detail.Summary,
			SourceURL:   le.Detail.Link,
			Title:       le.Detail.EventName,
			UniqueID:    le.ID,
		},
		Message: desc,
		Metadata: ocsf.Metadata{
			EventUID:     le.ID,
			OriginalTime: le.Time.Unix(),
			Product: ocsf.Product{
				Language:       "en",
				ProductID:      "lacework-polygraph-data-platform",
				ProductName:    "Lacework Polygraph Data Platform",
				ProductVersion: le.Version,
				VendorName:     "Lacework",
			},
			Version: VERSION,
		},
		SeverityID: int32(getOCSFSeverityID(le.Detail.Severity)),
		StateID:    ocsf.StateIDNew,
		TypeName:   "Security Finding: Generate",
		TypeID:     ocsf.TypeUIDGenerate,
	}
	return finding
}

func getOCSFSeverityID(s int) ocsf.SeverityID {
	switch s {
	case 1:
		return ocsf.SeverityIDCritical
	case 2:
		return ocsf.SeverityIDHigh
	case 3:
		return ocsf.SeverityIDMedium
	case 4:
		return ocsf.SeverityIDLow
	case 5:
		return ocsf.SeverityIDInformational
	}
	return ocsf.SeverityIDUnknown
}

func getTypes(m map[string]string, t string) []*string {
	var tList []*string

	tList = append(tList, aws.String(m[t]))

	return tList
}

func getAwsAccount(defaultAccount, data string) string {
	re := regexp.MustCompile("\\d{12}")
	match := re.FindStringSubmatch(data)
	if len(match) == 0 || match[0] == "" {
		return defaultAccount
	}
	return match[0]
}

func MapDefault(d lacework.Data, res securityhub.Resource) securityhub.Resource {
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EventActor)
	return res
}

func MapAwsApiTracker(d lacework.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Details.Other = make(map[string]*string)
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.CtUser[0].Username)
	res.Partition = aws.String("aws")
	res.Region = aws.String(d.EntityMap.Region[0].Region)
	for i, o := range d.EntityMap.API {
		if i < 50 {
			if o.Service != "" || o.API != "" {
				res.Details.Other[o.API] = aws.String(formatOnLength(o.Service, 1024))
			}
		}
	}
	return res
}

func MapCloudTrailCep(d lacework.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Details.Other = make(map[string]*string)
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.CtUser[0].Username)
	res.Partition = aws.String("aws")
	res.Region = aws.String(d.EntityMap.Region[0].Region)
	for i, o := range d.EntityMap.Resource {
		if i < 50 {
			res.Details.Other[o.Name] = aws.String(formatOnLength(o.Value, 1024))
		}
	}
	for i, o := range d.EntityMap.RulesTriggered {
		if i < 50 {
			res.Details.Other[o.RuleID] = aws.String(formatOnLength(o.RuleTitle, 1024))
		}
	}
	return res
}

func getDescription(input string) string {
	if len(input) >= 255 {
		return input[:255]
	} else {
		return input
	}
}

// getComplianceCloud returns the public cloud of the event (aws, gcp, azure) based on the event summary
func getComplianceCloud(input string) string {
	var cloud string
	if strings.Contains(strings.ToLower(input), "aws") {
		cloud = "aws"
	} else if strings.Contains(strings.ToLower(input), "gcp") {
		cloud = "gcp"
	} else if strings.Contains(strings.ToLower(input), "azure") {
		cloud = "azure"
	}
	return cloud
}

func formatOnLength(input string, length int) string {
	var output string
	l := len(input)
	if l < length {
		output = input
	} else {
		output = input[:length]
	}
	return output
}

func lastString(ss []string) string {
	return ss[len(ss)-1]
}

func isActive(value int) string {
	active := "false"
	if value > 0 {
		active = "true"
	}
	return active
}
