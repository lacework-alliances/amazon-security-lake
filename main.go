package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/jefferyfry/funclog"
	"github.com/lacework-alliances/aws-moose-integration/internal/findings"
	"github.com/lacework-alliances/aws-moose-integration/internal/honeycomb"
	"github.com/lacework-alliances/aws-moose-integration/pkg/lacework"
	"github.com/lacework-alliances/aws-moose-integration/pkg/ocsf"
	"github.com/xitongsys/parquet-go-source/s3"
	"github.com/xitongsys/parquet-go/writer"
	"log"
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
		fmt.Println("Please set the environment variable LACEWORK_INSTANCE")
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
		if len(f) > 0 {
			writeFindingToS3(ctx, f)
			if err != nil {
				if telemetry {
					honeycomb.SendHoneycombEvent(instance, "error", "", BUILD, err.Error(), "BatchImportFindings", DATASET, HONEYKEY)
				}
				LogE.Println("error while importing batch: ", err)
			}
		}
	}
}

func writeFindingToS3(ctx context.Context, findings []*ocsf.SecurityFinding) {
	bucket := mooseBucket
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	account := strings.Split(lc.InvokedFunctionArn, ":")[4]
	t := time.Now()
	key := fmt.Sprintf("region=%s/AWS_account=%s/eventhour=%s", region, account, t.Format("2006010215"))
	// create new S3 file writer
	fw, err := s3.NewS3FileWriter(ctx, bucket, key, "bucket-owner-full-control", nil)
	if err != nil {
		log.Println("Can't open S3 file", err)
		return
	}
	// create new parquet file writer
	pw, err := writer.NewParquetWriter(fw, new(ocsf.SecurityFinding), 4)
	if err != nil {
		LogW.Println("Can't open parquet write for S3 file", err)
		return
	}

	for _, finding := range findings {
		s, _ := json.MarshalIndent(finding, "", "\t")
		LogI.Printf("Writing security finding %s", string(s))
		if err := pw.Write(finding); err != nil {
			LogW.Println("Can't write finding", err)
		}
	}
	// write parquet file footer
	if err := pw.WriteStop(); err != nil {
		LogW.Println("WriteStop err", err)
	}

	err = fw.Close()
	if err != nil {
		LogW.Println("Error closing S3 file writer")
	}
	LogI.Println("Write Finished")
}
