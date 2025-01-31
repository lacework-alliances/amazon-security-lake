// bootstrap.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/events"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	awss3 "github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/xitongsys/parquet-go-source/s3"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
	"github.com/jefferyfry/funclog"
	//"github.com/aws/aws-sdk-go/service/sts"
	"github.com/lacework-alliances/amazon-security-lake/internal/findings"
	"github.com/lacework-alliances/amazon-security-lake/internal/honeycomb"
	"github.com/lacework-alliances/amazon-security-lake/pkg/lacework"
	"github.com/lacework-alliances/amazon-security-lake/pkg/ocsf"
)

// Constants (consolidated)
const (
	MAIN_BUILD    = "$BUILD"
	MAIN_HONEYKEY = "$HONEYKEY"
	MAIN_DATASET  = "$DATASET"
	// SETUP_BUILD   = "$BUILD"
	// SETUP_HONEYKEY = "$HONEYKEY"
	// SETUP_DATASET  = "$DATASET"
	CACHEKEY      = "LaceworkSecurityFindingsCache"
)

// Global Variables
var (
	LogI  = funclog.NewInfoLogger("INFO: ")
	LogW  = funclog.NewInfoLogger("WARN: ")
	LogE  = funclog.NewErrorLogger("ERROR: ")
	instance                  string
	telemetry                 bool
	securityLakeS3Location    string
	securityLakeCacheS3Bucket string
	securityLakeRoleArn       string
	securityLakeRoleExternalId	string
)

// Main entry point
func main() {
	mode := os.Getenv("MODE")
	fmt.Printf("MODE environment variable: %s\n", mode)
    if mode == "" {
        mode = "main"
    }
	//mode := flag.String("mode", "main", "Specify the mode: 'main' or 'setup'")
	//flag.Parse()

	switch mode {
	case "main":
		runMain()
	case "setup":
		runSetup()
	default:
		fmt.Println("Invalid mode. Use 'main' or 'setup'.")
		os.Exit(1)
	}
}

// Main logic
func runMain() {
	fmt.Println("Running main logic")

	instance = os.Getenv("lacework_url")
	if instance == "" {
		fmt.Println("Please set the environment variable lacework_url")
	}
	if disabled := os.Getenv("LW_DISABLE_TELEMETRY"); disabled != "" {
		telemetry = false
	} else {
		telemetry = true
	}
	securityLakeS3Location = os.Getenv("amazon_security_lake_s3_location")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_s3_location")
	}
	securityLakeCacheS3Bucket = os.Getenv("amazon_security_lake_cache_s3_bucket_name")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_cache_s3_bucket_name")
	}
	securityLakeRoleArn = os.Getenv("amazon_security_lake_role_arn")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_role_arn")
		return
	}
	securityLakeRoleExternalId = os.Getenv("amazon_security_lake_role_eid")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_role_eid")
		return
	}

	cfg := lacework.Config{
		Instance:     instance,
		Region:       os.Getenv("AWS_REGION"),
		Telemetry:    telemetry,
		Version:      MAIN_BUILD,
		HoneyDataset: MAIN_DATASET,
		HoneyKey:     MAIN_HONEYKEY,
	}
	ctx := context.WithValue(context.Background(), "config", cfg)
	lam.StartWithOptions(handler, lam.WithContext(ctx))
}

func handler(ctx context.Context, e events.SQSEvent) {
	var event lacework.LaceworkEvent
	var currFs []ocsf.SecurityFinding

	for _, message := range e.Records {
		LogI.Printf("%s \n", message.Body)

		err := json.Unmarshal([]byte(message.Body), &event)
		if err != nil {
			if telemetry {
				honeycomb.SendHoneycombEvent(instance, "error", "", MAIN_BUILD, err.Error(), "record", MAIN_DATASET, MAIN_HONEYKEY)
			}
			LogE.Printf("error while unmarshalling event message: %v\n", err)
		}

		f := findings.EventToOCSF(ctx, event)
		currFs = append(currFs, f...)
	}
	if len(currFs) > 0 {
		//check for cache
		exists, cacheErr := cacheExists(securityLakeCacheS3Bucket)
		if cacheErr != nil {
			LogW.Println("Error calling cacheExists!", cacheErr.Error())
			return
		}
		if exists {
			expired, expiredErr := cacheExpired(securityLakeCacheS3Bucket, event.Time)
			if expiredErr != nil {
				LogW.Println("Error calling cacheExpired!", expiredErr.Error())
				return
			}
			if expired {
				fs, lastEventTime, getErr := getCacheFindings()
				if getErr != nil {
					LogW.Println("Error calling getCacheFindings!", getErr.Error())
					return
				} else {
					writeErr := writeFindingsToAmazonSecurityLake(ctx, fs, lastEventTime)
					if writeErr != nil {
						LogW.Println("Error calling writeFindingsToAmazonSecurityLake!", writeErr.Error())
						return
					} else {
						deleteErr := deleteCache()
						if deleteErr != nil {
							LogW.Println("Error calling deleteCache!", deleteErr.Error())
							return
						} else {
							writeCacheErr := writeToNewCache(currFs, event.Time)
							if writeCacheErr != nil {
								LogW.Println("Error calling writeToNewCache!", writeCacheErr.Error())
								return
							}
						}
					}
				}
			} else {
				addErr := addToExistingCache(currFs, event.Time)
				if addErr != nil {
					LogW.Println("Error calling addToExistingCache!", addErr.Error())
					return
				}
			}
		} else {
			writeCacheErr := writeToNewCache(currFs, event.Time)
			if writeCacheErr != nil {
				LogW.Println("Error calling writeToNewCache!", writeCacheErr.Error())
				return
			}
		}
	}
}

func cacheExpired(bucket string, t time.Time) (bool, error) {
	svc := awss3.New(session.Must(session.NewSession()))
	input := &awss3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(CACHEKEY),
	}

	head, headErr := svc.HeadObject(input)
	if headErr != nil {
		LogW.Println("Error getting head object!", headErr.Error())
		return false, headErr
	}
	LogI.Println(head.Metadata)
	lastEventTimeStr := head.Metadata["Last-Event-Time"]
	unmarshText := aws.StringValue(lastEventTimeStr)
	LogI.Println("Cache time is", unmarshText)
	var cacheTimeTime time.Time
	eventTimeErr := cacheTimeTime.UnmarshalText([]byte(unmarshText))
	if eventTimeErr != nil {
		LogW.Println("Unable to unmarshal time from metadata to check cache expire!", securityLakeCacheS3Bucket, CACHEKEY, eventTimeErr.Error())
		return false, eventTimeErr
	}
	if t.Hour() != cacheTimeTime.Hour() {
		return true, nil
	}

	elapsed := t.Sub(cacheTimeTime)
	if elapsed.Minutes() > 5 && aws.Int64Value(head.ContentLength) > 256000000 {
		return true, nil
	}

	return false, nil
}

func addToExistingCache(fs []ocsf.SecurityFinding, lastEventTime time.Time) error {
	currFs, _, getErr := getCacheFindings()
	if getErr != nil {
		LogW.Println("Error calling getCacheFindings!", getErr.Error())
		return getErr
	}
	currFs = append(currFs, fs...)
	deleteErr := deleteCache()
	if deleteErr != nil {
		LogW.Println("Error calling deleteCache!", deleteErr.Error())
		return deleteErr
	}

	writeErr := writeToNewCache(currFs, lastEventTime)
	if writeErr != nil {
		LogW.Println("Error calling writeToNewCache!", writeErr.Error())
		return writeErr
	}
	return nil
}

func getCacheFindings() ([]ocsf.SecurityFinding, time.Time, error) {
	svc := awss3.New(session.Must(session.NewSession()))
	input := &awss3.GetObjectInput{
		Bucket: aws.String(securityLakeCacheS3Bucket),
		Key:    aws.String(CACHEKEY),
	}
	findings, getErr := svc.GetObject(input)
	if getErr != nil {
		LogW.Println("Unable to read findings from cache!", securityLakeCacheS3Bucket, CACHEKEY, getErr.Error())
		return nil, time.Time{}, getErr
	}

	defer findings.Body.Close()
	findingsBytes, readErr := io.ReadAll(findings.Body)
	if readErr != nil {
		LogW.Println("Unable to read findings from body!", securityLakeCacheS3Bucket, CACHEKEY, readErr.Error())
		return nil, time.Time{}, readErr
	}
	var fs []ocsf.SecurityFinding
	unmarshalErr := json.Unmarshal(findingsBytes, &fs)
	if unmarshalErr != nil {
		LogW.Println("Unable to unmarshal findings to get cache findings!", securityLakeCacheS3Bucket, CACHEKEY, unmarshalErr.Error())
		return nil, time.Time{}, unmarshalErr
	}
	LogI.Println(findings.Metadata)
	lastEventTimeStr := findings.Metadata["Last-Event-Time"]
	unmarshText := aws.StringValue(lastEventTimeStr)
	var lastEventTime time.Time
	eventTimeErr := lastEventTime.UnmarshalText([]byte(unmarshText))
	if eventTimeErr != nil {
		LogW.Println("Unable to get event time from cache!", securityLakeCacheS3Bucket, CACHEKEY, eventTimeErr.Error())
		return nil, time.Time{}, eventTimeErr
	}

	return fs, lastEventTime, nil
}

func deleteCache() error {
	svc := awss3.New(session.Must(session.NewSession()))
	input := &awss3.DeleteObjectInput{
		Bucket: aws.String(securityLakeCacheS3Bucket),
		Key:    aws.String(CACHEKEY),
	}

	_, deleteErr := svc.DeleteObject(input)
	if deleteErr != nil {
		LogW.Println("Unable to delete cache!", securityLakeCacheS3Bucket, CACHEKEY, deleteErr.Error())
		return deleteErr
	}
	return nil
}

func writeToNewCache(fs []ocsf.SecurityFinding, lastEventTime time.Time) error {
	json, err := json.Marshal(fs)
	if err != nil {
		LogW.Println("Unable to write to cache ", securityLakeCacheS3Bucket, err)
		return err
	}
	svc := awss3.New(session.Must(session.NewSession()))
	marshTime, marshErr := lastEventTime.MarshalText()
	if marshErr != nil {
		LogW.Println("Unable to marshal the event time ", lastEventTime, marshErr)
		return err
	}
	meta := map[string]*string{"last-event-time": aws.String(string(marshTime))}
	input := &awss3.PutObjectInput{
		Bucket:   aws.String(securityLakeCacheS3Bucket),
		Key:      aws.String(CACHEKEY),
		Body:     aws.ReadSeekCloser(bytes.NewReader(json)),
		Metadata: meta,
	}

	_, putErr := svc.PutObject(input)
	if putErr != nil {
		LogW.Println("Unable to write new cache!", securityLakeCacheS3Bucket, CACHEKEY, putErr.Error())
		return putErr
	}
	return nil
}

func cacheExists(bucket string) (bool, error) {
	svc := awss3.New(session.Must(session.NewSession()))
	input := &awss3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(CACHEKEY),
	}

	_, err := svc.HeadObject(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case awss3.ErrCodeNoSuchBucket:
				LogW.Println("aerr.Code()", aerr.Code(), bucket, CACHEKEY, aerr.Code(), aerr.Error())
			case awss3.ErrCodeNoSuchKey:
				return false, nil
			case "NotFound":
				return false, nil
			default:
				LogW.Println("aerr.Code()", aerr.Code(), bucket, CACHEKEY, aerr.Error())
			}
		} else {
			LogW.Println(bucket, CACHEKEY, err.Error())
		}
		return false, err
	} else {
		return true, nil
	}
}


func writeFindingsToAmazonSecurityLake(ctx context.Context, findings []ocsf.SecurityFinding, createTime time.Time) error {
    // Capture Lambda context details
    LogI.Println("This should appear in stdout")
    os.Stdout.Sync() // Ensure flushing
    lc, _ := lambdacontext.FromContext(ctx)
    region := strings.Split(lc.InvokedFunctionArn, ":")[3]
    account := strings.Split(lc.InvokedFunctionArn, ":")[4]

    // Validate S3 location
    bucket, path, fnd := strings.Cut(securityLakeS3Location, "/")
    if !fnd {
        LogE.Println("Invalid Amazon Security Lake S3 location", securityLakeS3Location)
        return errors.New("invalid Security Lake S3 location")
    }

    // Construct object key with detailed path
    objectKey := fmt.Sprintf("%s/region=%s/AWS_account=%s/eventDay=%s/%s.zstd.parquet", 
        path, region, account, createTime.Format("20060102"), createTime.Format(time.RFC3339))

    // Validate external ID
    LogI.Println("Validate external ID")
    securityLakeRoleExternalId := os.Getenv("amazon_security_lake_role_eid")
    if securityLakeRoleExternalId == "" {
        LogE.Println("Missing external ID for role assumption")
        return errors.New("external ID not configured")
    }

    // Detailed role assumption logging
    LogI.Printf("Role Assumption Details:")
    LogI.Printf("- Target Role ARN: %s", securityLakeRoleArn)
    LogI.Printf("- AWS Account: %s", account)
    LogI.Printf("- Region: %s", region)
    LogI.Printf("- External ID: %s (masked)", maskExternalID(securityLakeRoleExternalId))
    os.Stdout.Sync()

    // Create AWS session
    sess := session.Must(session.NewSession(&aws.Config{
        Region: aws.String(region),
    }))

    // Assume role with detailed credential logging
    LogI.Println("Testing log statement before AssumeRole")
    creds, err := assumeRoleWithLogging(sess, securityLakeRoleArn, securityLakeRoleExternalId)
    if err != nil {
        LogE.Printf("Role assumption failed: %v", err)
        os.Stderr.Sync() // Sync for ERROR-level logs
        return fmt.Errorf("role assumption error: %w", err)
    }

    // S3 file write logging preparation
    LogI.Printf("S3 Write Configuration:")
    LogI.Printf("- Bucket: %s", bucket)
    LogI.Printf("- Object Key: %s", objectKey)
    LogI.Printf("- Findings Count: %d", len(findings))
    os.Stdout.Sync()

    // Create S3 file writer
    fw, err := s3.NewS3FileWriter(ctx, bucket, objectKey, "bucket-owner-full-control", nil, &aws.Config{
        Credentials: creds,
        Region:      aws.String(region),
    })
    if err != nil {
        LogE.Printf("S3 File Writer Creation Failed: %v", err)
        os.Stderr.Sync() // Sync for ERROR-level logs
        return fmt.Errorf("s3 writer error: %w", err)
    }
    defer fw.Close()

    // Parquet writer setup
    pw, err := writer.NewParquetWriter(fw, new(ocsf.SecurityFinding), 4)
    if err != nil {
        LogE.Printf("Parquet Writer Creation Failed: %v", err)
        os.Stderr.Sync() // Sync for ERROR-level logs
        return fmt.Errorf("parquet writer error: %w", err)
    }
    pw.CompressionType = parquet.CompressionCodec_ZSTD

    // Write findings with error tracking
    var writtenCount int
    for _, finding := range findings {
        if err := pw.Write(finding); err != nil {
            LogE.Printf("Finding Write Error: %v", err)
            os.Stderr.Sync() // Sync for ERROR-level logs
            return fmt.Errorf("finding write error: %w", err)
        }
        writtenCount++
    }

    // Finalize parquet file
    if err := pw.WriteStop(); err != nil {
        LogE.Printf("Parquet Write Finalization Error: %v", err)
        os.Stderr.Sync() // Sync for ERROR-level logs
        return fmt.Errorf("parquet finalization error: %w", err)
    }

    LogI.Printf("S3 Write Completed Successfully:")
    LogI.Printf("- Total Findings Written: %d", writtenCount)
    
    return nil
}

// Helper function for role assumption with logging
func assumeRoleWithLogging(sess *session.Session, roleArn, externalID string) (*credentials.Credentials, error) {
    stsClient := sts.New(sess)
    
    input := &sts.AssumeRoleInput{
        RoleArn:         aws.String(roleArn),
        RoleSessionName: aws.String("SecurityLakeAssumeRole"),
        ExternalId:      aws.String(externalID),
    }

    result, err := stsClient.AssumeRole(input)
    if err != nil {
        LogE.Printf("STS AssumeRole Failed: %v", err)
        return nil, err
    }

    LogI.Printf("Role Assumed Successfully:")
    LogI.Printf("- Session Duration: %v", result.Credentials.Expiration.Sub(time.Now()))

    return credentials.NewStaticCredentials(
        *result.Credentials.AccessKeyId, 
        *result.Credentials.SecretAccessKey, 
        *result.Credentials.SessionToken,
    ), nil
}

// Mask external ID for logging security
func maskExternalID(id string) string {
    if len(id) <= 4 {
        return "****"
    }
    return id[:2] + "**" + id[len(id)-2:]
}



func runSetup() {
	//fmt.Println("Running setup logic")
	LogI.Println("Starting setup logic")
	cfnLambda := cfn.LambdaWrap(handlerSetup)
	lam.Start(cfnLambda)

}


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


func handlerSetup(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	LogI.Printf("Handler setup invoked with event: %+v", event)
	if event.RequestType == cfn.RequestCreate {
		return create(ctx, event)
	} else if event.RequestType == cfn.RequestDelete {
		return delete(ctx, event)
	} else {
		LogW.Println("CloudFormation event not supported: ", event.RequestType)
		return "", nil, nil
	}
}

func create(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
		LogI.Printf("Create function called with event: %+v", event)
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
		LogI.Printf("Delete function called with event: %+v", event)
		LogISetup.Printf("CloudFormation event received: %+v \n", event)
		laceworkUrl := os.Getenv("lacework_url")
		subAccountName := os.Getenv("lacework_sub_account_name")
		accessKeyId := os.Getenv("lacework_access_key_id")
		secretKey := os.Getenv("lacework_secret_key")
		alertChannelName := os.Getenv("alert_channel_name")
		securityLakeCacheS3Bucket := os.Getenv("amazon_security_lake_cache_s3_bucket_name")
		honeycomb.SendHoneycombEvent(strings.Split(laceworkUrl, ".")[0], "delete started", subAccountName, SBUILD, "{}", "{}", SDATASET, SHONEYKEY)

		//empty the cache bucket
		svc := awss3.New(session.Must(session.NewSession()))
		input := &awss3.DeleteObjectInput{
			Bucket: aws.String(securityLakeCacheS3Bucket),
			Key:    aws.String("LaceworkSecurityFindingsCache"),
		}

		_, deleteErr := svc.DeleteObject(input)
		if deleteErr != nil {
			LogWSetup.Println("Unable to delete cache!", securityLakeCacheS3Bucket, deleteErr.Error())
		}

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

// Shared utility functions
// Consolidate shared functionality, such as cache operations, here
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
				respDump, err := httputil.DumpResponse(resp, true)
				if err != nil {
					LogWSetup.Println(err)
				} else {
					LogWSetup.Printf("Received response: %s", string(respDump))
				}
				return "", errors.New(fmt.Sprintf("Failed sending alert channel request. Response status is %s", resp.Status))
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
