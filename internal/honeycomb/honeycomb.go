package honeycomb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"net/http"
)

const (
	techPartner     = "AWS"
	integrationName = "lacework-aws-moose-alert"
	service         = "AWS Moose"
	installMethod   = "cloudformation"
)

func SendHoneycombEvent(account string, event string, subAccountName string, version string, eventData string, f string, dataset string, key string) {
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
		url := fmt.Sprintf("https://api.honeycomb.io/1/events/%s", dataset)
		if request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payloadBytes)); err == nil {
			request.Header.Add("X-Honeycomb-Team", key)
			request.Header.Add("content-type", "application/json")
			if resp, err := http.DefaultClient.Do(request); err == nil {
				fmt.Printf("Sent event to Honeycomb: %s %d\n", event, resp.StatusCode)
			} else {
				fmt.Printf("Unable to send event to Honeycomb: %s\n", err)
			}
		}
	}
}
