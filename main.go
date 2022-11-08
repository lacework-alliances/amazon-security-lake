package main

import (
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
	"github.com/lacework-alliances/aws-moose-integration/internal/findings"
	"github.com/lacework-alliances/aws-moose-integration/internal/honeycomb"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"github.com/lacework-alliances/aws-moose-integration/pkg/ocsf"
	"github.com/xitongsys/parquet-go-source/s3"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/reader"
	"github.com/xitongsys/parquet-go/writer"
	"os"
	"strings"
	"time"
)

const (
	BUILD    = "$BUILD"
	HONEYKEY = "$HONEYKEY"
	DATASET  = "$DATASET"
)

var (
	instance    string
	telemetry   bool
	mooseBucket string
	LogI        = funclog.NewInfoLogger("INFO: ")
	LogW        = funclog.NewInfoLogger("WARN: ")
	LogE        = funclog.NewErrorLogger("ERROR: ")
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
	mooseBucket = os.Getenv("moose_s3_bucket_name")
	if instance == "" {
		fmt.Println("Please set the environment variable LACEWORK_INSTANCE")
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
		key := getBucketKey(ctx)
		if s3BucketKeyExists(mooseBucket, key) {
			LogI.Println("S3 bucket and key exist", mooseBucket, key)
			s3Fs := readFindingsFromS3(ctx, mooseBucket, key)
			if s3Fs != nil {
				LogI.Println("Append currFs to s3Fs", len(s3Fs), len(currFs))
				currFs = append(s3Fs, currFs...)
			}
		}
		writeFindingToS3(ctx, mooseBucket, key, currFs)
	}
}

func s3BucketKeyExists(bucket string, key string) bool {
	svc := awss3.New(session.New())
	input := &awss3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := svc.HeadObject(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				LogW.Println(bucket, key, aerr.Error())
			}
		} else {
			LogW.Println(bucket, key, err.Error())
		}
		return false
	} else {
		return true
	}
}

func readFindingsFromS3(ctx context.Context, bucket string, key string) []ocsf.SecurityFinding {
	// read the written parquet file
	// create new S3 file reader
	fr, err := s3.NewS3FileReader(ctx, bucket, key)
	if err != nil {
		LogE.Println("Can't open S3 file for read", bucket, key, err)
		return nil
	}

	// create new parquet file reader
	pr, err := reader.NewParquetReader(fr, new(ocsf.SecurityFinding), 4)
	if err != nil {
		LogE.Println("Can't create parquet reader", err)
		return nil
	}

	num := int(pr.GetNumRows())
	LogI.Println("Reading num findings", num)
	fs := make([]ocsf.SecurityFinding, num)
	if err = pr.Read(&fs); err != nil {
		LogE.Println("Read error reading from S3 file", bucket, key, err)
		return nil
	}

	// close the parquet file
	pr.ReadStop()
	err = fr.Close()
	if err != nil {
		LogE.Println("Error closing S3 file reader", bucket, key, err)
		return nil
	}
	LogI.Println("Read Finished")
	return fs
}

func getBucketKey(ctx context.Context) string {
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	account := strings.Split(lc.InvokedFunctionArn, ":")[4]
	t := time.Now()
	return fmt.Sprintf("region=%s/AWS_account=%s/eventhour=%s", region, account, t.Format("2006010215"))
}

func writeFindingToS3(ctx context.Context, bucket string, key string, findings []ocsf.SecurityFinding) {
	// create new S3 file writer
	fw, err := s3.NewS3FileWriter(ctx, bucket, key, "bucket-owner-full-control", nil)
	if err != nil {
		LogE.Println("Can't open S3 file for write", bucket, key, err)
		return
	}
	// create new parquet file writer
	pw, err := writer.NewParquetWriter(fw, new(ocsf.SecurityFinding), 4)
	if err != nil {
		LogW.Println("Can't open parquet write for S3 file", bucket, key, err)
		return
	}
	pw.CompressionType = parquet.CompressionCodec_ZSTD

	LogI.Println("Writing findings", key, len(findings))
	for _, finding := range findings {
		s, _ := json.MarshalIndent(finding, "", "\t")
		LogI.Printf("Writing security finding %s", string(s))
		if err := pw.Write(finding); err != nil {
			LogW.Println("Can't write finding", bucket, key, err)
		}
	}
	// write parquet file footer
	if err := pw.WriteStop(); err != nil {
		LogW.Println("WriteStop err", bucket, key, err)
	}

	err = fw.Close()
	if err != nil {
		LogW.Println("Error closing S3 file writer", bucket, key, err)
	}
	LogI.Println("Write Finished")
}
