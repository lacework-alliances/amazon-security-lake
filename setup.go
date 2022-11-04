package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/cfn"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/jefferyfry/funclog"
	"github.com/lacework-alliances/aws-moose-integration/internal/honeycomb"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

const (
	SBUILD    = "$BUILD"
	SHONEYKEY = "$HONEYKEY"
	SDATASET  = "$DATASET"
)

var (
	LogISetup = funclog.NewInfoLogger("INFO: ")
	LogWSetup = funclog.NewInfoLogger("WARN: ")
	LogESetup = funclog.NewErrorLogger("ERROR: ")
)

type AccessTokenRequestPayload struct {
	KeyId      string `json:"keyId"`
	ExpiryTime int    `json:"expiryTime"`
}

type AccessTokenResponsePayload struct {
	ExpiresAt string `json:"expiresAt"`
	Token     string `json:"token"`
}

type AlertChannelRequestPayload struct {
	Name    string                        `json:"name"`
	Type    string                        `json:"type"`
	Enabled int                           `json:"enabled"`
	Data    AlertChannelRequestDataObject `json:"data"`
}

type AlertChannelRequestDataObject struct {
	IssueGrouping string `json:"issueGrouping"`
	EventBusArn   string `json:"eventBusArn"`
}

type AlertChannelResponsePayload struct {
	Data AlertChannelResponseDataObject `json:"data"`
}

type AlertChannelResponseDataObject struct {
	CreatedOrUpdatedBy   string          `json:"createdOrUpdatedBy"`
	CreatedOrUpdatedTime string          `json:"createdOrUpdatedTime"`
	Enabled              int             `json:"enabled"`
	IntgGuid             string          `json:"intgGuid"`
	IsOrg                int             `json:"isOrg"`
	Name                 string          `json:"name"`
	Props                json.RawMessage `json:"props"`
	State                json.RawMessage `json:"state"`
	Type                 string          `json:"type"`
	Data                 json.RawMessage `json:"data"`
}

type AlertRuleRequestPayload struct {
	Filters      AlertRuleFiltersArray `json:"filters"`
	IntgGuidList []string              `json:"intgGuidList"`
	Type         string                `json:"type"`
}

type AlertRuleFiltersArray struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Enabled        int      `json:"enabled"`
	ResourceGroups []string `json:"resourceGroups"`
	EventCategory  []string `json:"eventCategory"`
	Severity       []int    `json:"severity"`
}

type FilterPayload struct {
	Filters []FilterExpression `json:"filters"`
	Returns []string           `json:"returns"`
}

type FilterExpression struct {
	Expression string   `json:"expression"`
	Field      string   `json:"field"`
	Value      string   `json:"value,omitempty"`
	Values     []string `json:"values,omitempty"`
}

type SearchAlertChannelResponsePayload struct {
	Data []struct {
		IntgGuid string `json:"intgGuid"`
		Data     struct {
			IssueGrouping string `json:"issueGrouping"`
			EventBusArn   string `json:"eventBusArn"`
		} `json:"data"`
	} `json:"data"`
}

type SearchAlertRuleResponsePayload struct {
	Data []struct {
		McGuid string `json:"mcGuid"`
	} `json:"data"`
}

/*
*
Setup Functions
*/
func main() {
	lam.Start(cfn.LambdaWrap(handlerSetup))
}

func handlerSetup(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	if event.RequestType == cfn.RequestCreate {
		return create(ctx, event)
	} else if event.RequestType == cfn.RequestDelete {
		return delete(ctx, event)
	} else {
		LogWSetup.Println("CloudFormation event not supported: ", event.RequestType)
		return "", nil, nil
	}
}

func create(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	LogISetup.Printf("CloudFormation event received: %+v \n", event)
	laceworkUrl := os.Getenv("lacework_url")
	subAccountName := os.Getenv("lacework_sub_account_name")
	accessKeyId := os.Getenv("lacework_access_key_id")
	secretKey := os.Getenv("lacework_secret_key")
	eventBusArn := os.Getenv("event_bus_arn")
	alertChannelName := os.Getenv("alert_channel_name")
	honeycomb.SendHoneycombEvent(strings.Split(laceworkUrl, ".")[0], "create started", subAccountName, SBUILD, "{}", "{}", SDATASET, SHONEYKEY)

	valid := true

	if laceworkUrl == "" {
		LogESetup.Println("laceworkUrl was not set.")
		valid = false
	}

	if subAccountName == "" {
		LogWSetup.Println("laceworkSubAccountName was not set.")
	}

	if accessKeyId == "" {
		LogESetup.Println("laceworkAccessKeyId was not set.")
		valid = false
	}

	if secretKey == "" {
		LogESetup.Println("laceworkSecretKey was not set.")
		valid = false
	}

	if eventBusArn == "" {
		LogESetup.Println("eventBusArn was not set.")
		valid = false
	}

	if !valid {
		return event.PhysicalResourceID, nil, errors.New("unable to run setup due to missing required environment variables")
	}

	LogISetup.Println("Getting access token.")
	if accessToken, err := createAccessToken(laceworkUrl, accessKeyId, secretKey); err == nil {
		LogISetup.Println("Creating Alert Channel.")
		if intgGuid, err := createAlertChannel(alertChannelName, eventBusArn, laceworkUrl, accessToken, subAccountName); err == nil {
			LogISetup.Println("Creating Alert Rule.")
			if err := createAlertRule(alertChannelName, intgGuid, laceworkUrl, accessToken, subAccountName); err != nil {
				return event.PhysicalResourceID, nil, err
			}
		} else {
			errMsg := fmt.Sprintf("Failed creating alert channel: %v", err)
			LogESetup.Println(errMsg)
			return event.PhysicalResourceID, nil, err
		}
	} else {
		return event.PhysicalResourceID, nil, err
	}

	honeycomb.SendHoneycombEvent(strings.Split(laceworkUrl, ".")[0], "create completed", subAccountName, SBUILD, "{}", "{}", SDATASET, SHONEYKEY)
	return event.PhysicalResourceID, nil, nil
}

func delete(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	LogISetup.Printf("CloudFormation event received: %+v \n", event)
	laceworkUrl := os.Getenv("lacework_url")
	subAccountName := os.Getenv("lacework_sub_account_name")
	accessKeyId := os.Getenv("lacework_access_key_id")
	secretKey := os.Getenv("lacework_secret_key")
	alertChannelName := os.Getenv("alert_channel_name")
	honeycomb.SendHoneycombEvent(strings.Split(laceworkUrl, ".")[0], "delete started", subAccountName, SBUILD, "{}", "{}", SDATASET, SHONEYKEY)

	if accessToken, err := createAccessToken(laceworkUrl, accessKeyId, secretKey); err == nil {
		if intgGuid, err := searchAlertChannels(alertChannelName, laceworkUrl, accessToken, subAccountName); err == nil {
			deleteAlertChannel(intgGuid, laceworkUrl, accessToken, subAccountName)
		} else {
			LogWSetup.Printf("Unable to search: %v", err)
		}

		if mcGuid, err := searchAlertRules(alertChannelName, laceworkUrl, accessToken, subAccountName); err == nil {
			deleteAlertRule(mcGuid, laceworkUrl, accessToken, subAccountName)
		} else {
			LogWSetup.Printf("Unable to search: %v", err)
		}
	} else {
		LogWSetup.Println("Did not get access token in order to delete alert channel and alert rule.")
	}

	honeycomb.SendHoneycombEvent(strings.Split(laceworkUrl, ".")[0], "delete completed", subAccountName, SBUILD, "{}", "{}", SDATASET, SHONEYKEY)

	return event.PhysicalResourceID, nil, nil
}

func createAccessToken(laceworkUrl string, accessKeyId string, secretKey string) (string, error) {
	requestPayload := AccessTokenRequestPayload{
		KeyId:      accessKeyId,
		ExpiryTime: 86400,
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		request, err := http.NewRequest(http.MethodPost, "https://"+laceworkUrl+"/api/v2/access/tokens", bytes.NewBuffer(payloadBytes))

		if err != nil {
			return "", err
		}

		request.Header.Add("X-LW-UAKS", secretKey)
		request.Header.Add("content-type", "application/json")

		if resp, err := http.DefaultClient.Do(request); err == nil {
			defer resp.Body.Close()
			respData := AccessTokenResponsePayload{}
			if err := json.NewDecoder(resp.Body).Decode(&respData); err == nil {
				LogISetup.Printf("AccessTokenResponsePayload: %+v", respData)
			} else {
				LogESetup.Printf("Unable to get response body: %v", err)
				return "", err
			}
			if resp.StatusCode == http.StatusCreated {
				return respData.Token, nil
			} else {
				return "", errors.New(fmt.Sprintf("Failed to get access token. Response status is %d", resp.StatusCode))
			}
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func createAlertChannel(name string, eventBusArn string, laceworkUrl string, accessToken string, subAccountName string) (string, error) {
	requestPayload := AlertChannelRequestPayload{
		Name:    name,
		Type:    "CloudwatchEb",
		Enabled: 1,
		Data: AlertChannelRequestDataObject{
			IssueGrouping: "Events",
			EventBusArn:   eventBusArn,
		},
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		if resp, err := sendApiPostRequest(laceworkUrl, "/api/v2/AlertChannels", accessToken, payloadBytes, subAccountName); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				respData := AlertChannelResponsePayload{}
				if err := json.NewDecoder(resp.Body).Decode(&respData); err == nil {
					respDump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						LogWSetup.Println(err)
					}
					LogISetup.Printf("Received response: %s", string(respDump))
					return respData.Data.IntgGuid, nil
				} else {
					LogESetup.Printf("Unable to get response body: %v", err)
					return "", err
				}
			} else {
				return "", errors.New(fmt.Sprintf("Failed sending alert channel request. Response status is %d", resp.StatusCode))
			}

		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func deleteAlertChannel(intgGuid string, laceworkUrl string, accessToken string, subAccountName string) error {
	if resp, err := sendApiDeleteRequest(laceworkUrl, "/api/v2/AlertChannels/"+intgGuid, accessToken, subAccountName); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil
		} else {
			return errors.New(fmt.Sprintf("Failed sending delete alert channel request. Response status is %d", resp.StatusCode))
		}

	} else {
		return err
	}
}

func searchAlertChannels(name string, laceworkUrl string, accessToken string, subAccountName string) (string, error) {
	requestPayload := FilterPayload{
		Filters: []FilterExpression{
			{
				Expression: "eq",
				Field:      "name",
				Value:      name,
			},
		},
		Returns: []string{
			"intgGuid",
		},
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		if resp, err := sendApiPostRequest(laceworkUrl, "/api/v2/AlertChannels/search", accessToken, payloadBytes, subAccountName); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				respData := SearchAlertChannelResponsePayload{}
				if err := json.NewDecoder(resp.Body).Decode(&respData); err == nil {
					respDump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						LogWSetup.Println(err)
					}
					LogISetup.Printf("Received response: %s", string(respDump))
					if len(respData.Data) == 0 {
						LogWSetup.Println("No results returned.")
						return "", err
					} else {
						return respData.Data[0].IntgGuid, nil
					}
				} else {
					LogESetup.Printf("Unable to get response body: %v", err)
					return "", err
				}
			} else {
				return "", errors.New(fmt.Sprintf("Failed sending search request. Response status is %d", resp.StatusCode))
			}
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func createAlertRule(name string, intgGuid string, laceworkUrl string, accessToken string, subAccountName string) error {
	requestPayload := AlertRuleRequestPayload{
		Filters: AlertRuleFiltersArray{
			Name:           name,
			Description:    "Alert rule for Lacework AWS Security Hub",
			Enabled:        1,
			ResourceGroups: []string{},
			EventCategory:  []string{},
			Severity:       []int{1, 2, 3, 4, 5},
		},
		IntgGuidList: []string{intgGuid},
		Type:         "Event",
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		if resp, err := sendApiPostRequest(laceworkUrl, "/api/v2/AlertRules", accessToken, payloadBytes, subAccountName); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				respDump, err := httputil.DumpResponse(resp, true)
				if err != nil {
					LogWSetup.Println(err)
				}
				LogISetup.Printf("Received response: %s", string(respDump))
				return nil
			} else {
				return errors.New(fmt.Sprintf("Failed sending alert rule request. Response status is %d", resp.StatusCode))
			}
		} else {
			return err
		}
	} else {
		return err
	}
}

func deleteAlertRule(mcGuid string, laceworkUrl string, accessToken string, subAccountName string) error {
	if resp, err := sendApiDeleteRequest(laceworkUrl, "/api/v2/AlertRules/"+mcGuid, accessToken, subAccountName); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return nil
		} else {
			return errors.New(fmt.Sprintf("Failed sending delete alert channel request. Response status is %d", resp.StatusCode))
		}

	} else {
		return err
	}
}

func searchAlertRules(name string, laceworkUrl string, accessToken string, subAccountName string) (string, error) {
	requestPayload := FilterPayload{
		Filters: []FilterExpression{
			{
				Expression: "eq",
				Field:      "filters.name",
				Value:      name,
			},
		},
		Returns: []string{
			"mcGuid",
		},
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		if resp, err := sendApiPostRequest(laceworkUrl, "/api/v2/AlertRules/search", accessToken, payloadBytes, subAccountName); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				respData := SearchAlertRuleResponsePayload{}
				if err := json.NewDecoder(resp.Body).Decode(&respData); err == nil {
					respDump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						LogWSetup.Println(err)
					}
					LogISetup.Printf("Received response: %s", string(respDump))
					if len(respData.Data) == 0 {
						LogWSetup.Println("No results returned.")
						return "", err
					} else {
						return respData.Data[0].McGuid, nil
					}
				} else {
					LogESetup.Printf("Unable to get response body: %v", err)
					return "", err
				}
			} else {
				return "", errors.New(fmt.Sprintf("Failed sending search request. Response status is %d", resp.StatusCode))
			}
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func sendApiPostRequest(laceworkUrl string, api string, accessToken string, requestPayload []byte, subAccountName string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, "https://"+laceworkUrl+api, bytes.NewBuffer(requestPayload))

	if err != nil {
		LogESetup.Printf("Error creating API post request: %v %v\n", err, requestPayload)
		return nil, err
	}

	request.Header.Add("Authorization", accessToken)
	request.Header.Add("content-type", "application/json")

	if subAccountName != "" {
		request.Header.Add("Account-Name", subAccountName)
	}

	requestDump, err := httputil.DumpRequest(request, true)
	if err != nil {
		LogWSetup.Println(err)
	}
	LogISetup.Printf("Sending request: %s", string(requestDump))

	return http.DefaultClient.Do(request)
}

func sendApiDeleteRequest(laceworkUrl string, api string, accessToken string, subAccountName string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodDelete, "https://"+laceworkUrl+api, nil)

	if err != nil {
		LogESetup.Printf("Error creating API delete request: %v\n", err)
		return nil, err
	}

	request.Header.Add("Authorization", accessToken)
	request.Header.Add("content-type", "application/json")

	if subAccountName != "" {
		request.Header.Add("Account-Name", subAccountName)
	}

	requestDump, err := httputil.DumpRequest(request, true)
	if err != nil {
		LogWSetup.Println(err)
	}
	LogISetup.Printf("Sending request: %s", string(requestDump))

	return http.DefaultClient.Do(request)
}
