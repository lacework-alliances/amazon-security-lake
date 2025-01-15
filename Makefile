BUCKET_NAME := lacework-alliances
KEY_PREFIX := lacework-amazon-security-lake
LAMBDA_PREFIX := lambda/
CFT_PREFIX := templates/
HONEY_DATASET := lacework-alliances-dev

PROFILE ?= ct
REGION ?= us-west-2

all: build

clean:
	rm -f bootstrap amazon-security-lake.zip

build: clean
	@buildid=$$(git describe --all --long | cut -d "/" -f 2); \
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o bootstrap bootstrap.go
	mkdir -p package
	cp bootstrap package/bootstrap
	cd package && zip amazon-security-lake.zip bootstrap
	@aws --region $(REGION) s3 cp package/amazon-security-lake.zip s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(LAMBDA_PREFIX) --acl public-read
	@aws --region $(REGION) s3 cp amazon-security-lake-integration.yml s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(CFT_PREFIX) --acl public-read
	rm bootstrap || true
	rm -rf package || true
