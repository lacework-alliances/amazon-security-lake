package honeycomb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"net/http"
)

var (
	// HoneyApiKey is a variable that is injected at build time via
	// the cross-platform directive inside the Makefile, this key is
	// used to send events to Honeycomb so that we can understand how
	// our customers use the Lacework CLI
	HoneyApiKey = ""

	// HoneyDataset is the dataset in Honeycomb that we send tracing
	// data this variable will be set depending on the environment we
	// are running on. During development, we send all events and
	// tracing data to a default dataset.
	HoneyDataset = "lacework-alliances-dev"
)

const (
	techPartner     = "AWS"
	integrationName = "lacework-aws-moose-alert"
	service         = "AWS Moose"
	installMethod   = "cloudformation"
)

func SendHoneycombEvent(account string, event string, subAccountName string, version string, eventData string, f string) {
	if eventData == "" {
		eventData = "{}"
	}

	requestPayload := lacework.Honeyvent{
		Account:         account,
		SubAccount:      subAccountName,
		TechPartner:     techPartner,
		IntegrationName: integrationName,
		Version:         version,
		Service:         service,
		InstallMethod:   installMethod,
		Function:        f,
		Event:           event,
		EventData:       eventData,
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		url := fmt.Sprintf("https://api.honeycomb.io/1/events/%s", HoneyDataset)
		if request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payloadBytes)); err == nil {
			request.Header.Add("X-Honeycomb-Team", HoneyApiKey)
			request.Header.Add("content-type", "application/json")
			if resp, err := http.DefaultClient.Do(request); err == nil {
				fmt.Printf("Sent event to Honeycomb: %s %d\n", event, resp.StatusCode)
			} else {
				fmt.Printf("Unable to send event to Honeycomb: %s\n", err)
			}
		}
	}
}
