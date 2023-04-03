package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	awss3 "github.com/aws/aws-sdk-go/service/s3"
	"github.com/jefferyfry/funclog"
	"github.com/lacework-alliances/amazon-security-lake/internal/findings"
	"github.com/lacework-alliances/amazon-security-lake/internal/honeycomb"
	"github.com/lacework-alliances/amazon-security-lake/pkg/lacework"
	"github.com/lacework-alliances/amazon-security-lake/pkg/ocsf"
	"github.com/xitongsys/parquet-go-source/s3"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
	"io"
	"os"
	"strings"
	"time"
)

const (
	BUILD    = "$BUILD"
	HONEYKEY = "$HONEYKEY"
	DATASET  = "$DATASET"
	CACHEKEY = "LaceworkSecurityFindingsCache"
)

var (
	instance                  string
	telemetry                 bool
	securityLakeS3Bucket      string
	securityLakeCacheS3Bucket string
	LogI                      = funclog.NewInfoLogger("INFO: ")
	LogW                      = funclog.NewInfoLogger("WARN: ")
	LogE                      = funclog.NewErrorLogger("ERROR: ")
)

func init() {
	instance = os.Getenv("lacework_url")
	if instance == "" {
		fmt.Println("Please set the environment variable lacework_url")
	}
	if disabled := os.Getenv("LW_DISABLE_TELEMETRY"); disabled != "" {
		telemetry = false
	} else {
		telemetry = true
	}
	securityLakeS3Bucket = os.Getenv("amazon_security_lake_s3_bucket_name")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_s3_bucket_name")
	}
	securityLakeCacheS3Bucket = os.Getenv("amazon_security_lake_cache_s3_bucket_name")
	if instance == "" {
		fmt.Println("Please set the environment variable amazon_security_lake_cache_s3_bucket_name")
	}
}

func main() {
	cfg := lacework.Config{
		Instance:     instance,
		EventMap:     findings.InitMap(),
		Region:       os.Getenv("AWS_REGION"),
		Telemetry:    telemetry,
		Version:      BUILD,
		HoneyDataset: DATASET,
		HoneyKey:     HONEYKEY,
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
				honeycomb.SendHoneycombEvent(instance, "error", "", BUILD, err.Error(), "record", DATASET, HONEYKEY)
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
	svc := awss3.New(session.New())
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
	svc := awss3.New(session.New())
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
	svc := awss3.New(session.New())
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
	svc := awss3.New(session.New())
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
	svc := awss3.New(session.New())
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
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	account := strings.Split(lc.InvokedFunctionArn, ":")[4]
	objectKey := fmt.Sprintf("region=%s/AWS_account=%s/eventDay=%s/%s.zstd.parquet", region, account, createTime.Format("2006010215"), createTime.Format(time.RFC3339))

	// create new S3 file writer
	fw, err := s3.NewS3FileWriter(ctx, securityLakeS3Bucket, objectKey, "bucket-owner-full-control", nil)
	if err != nil {
		LogE.Println("Can't open S3 file for write", securityLakeS3Bucket, objectKey, err)
		return err
	}
	// create new parquet file writer
	pw, err := writer.NewParquetWriter(fw, new(ocsf.SecurityFinding), 4)
	if err != nil {
		LogW.Println("Can't open parquet write for S3 file", securityLakeS3Bucket, objectKey, err)
		return err
	}
	pw.CompressionType = parquet.CompressionCodec_ZSTD

	LogI.Println("Writing findings", CACHEKEY, len(findings))
	for _, finding := range findings {
		s, _ := json.MarshalIndent(finding, "", "\t")
		LogI.Printf("Writing security finding %s", string(s))
		if err := pw.Write(finding); err != nil {
			LogW.Println("Can't write finding", securityLakeS3Bucket, objectKey, err)
			return err
		}
	}
	// write parquet file footer
	if err := pw.WriteStop(); err != nil {
		LogW.Println("WriteStop err", securityLakeS3Bucket, objectKey, err)
		return err
	}

	err = fw.Close()
	if err != nil {
		LogW.Println("Error closing S3 file writer", securityLakeS3Bucket, objectKey, err)
		return err
	}
	LogI.Println("Write Finished")
	return nil
}
