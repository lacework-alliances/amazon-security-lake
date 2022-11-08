package findings

import (
	"context"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"github.com/lacework-alliances/aws-moose-integration/pkg/ocsf"
)

type Compliance struct {
	Event  lacework.LaceworkEvent
	config lacework.Config
}

func (c *Compliance) Findings(ctx context.Context) []ocsf.SecurityFinding {
	var fs []ocsf.SecurityFinding
	// determine what cloud provider
	cloud := getComplianceCloud(c.Event.Detail.Summary)
	// grab the config struct from the context
	c.config = ctx.Value("config").(lacework.Config)
	for _, data := range c.Event.Detail.EventDetails.Data {
		finding := mapDefault(ctx, c.Event)
		c.enrich(finding, cloud, data)
		fs = append(fs, finding)
	}
	return fs
}

func (c *Compliance) enrich(finding ocsf.SecurityFinding, cloud string, data lacework.Data) {
	if len(data.EntityMap.NewViolation) > 0 {
		finding.ResourcesArray = append(finding.ResourcesArray, ocsf.Resource{
			Name: data.EntityMap.NewViolation[0].Resource,
		})
	}
}
