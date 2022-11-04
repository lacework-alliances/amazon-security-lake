BUCKET_NAME := lacework-alliances
KEY_PREFIX := lacework-moose
LAMBDA_PREFIX := lambda/
CFT_PREFIX := templates/
HONEY_DATASET := lacework-alliances-dev

PROFILE ?= ct
REGION ?= us-west-2

all: build

.PHONY: clean build

clean:
	rm main || true
	rm main_new.go || true
	rm setup || true
	rm setup_new.go || true
	rm moose.zip || true

build: clean
	buildid=$$(git describe --all --long | cut -d "/" -f 2); \
	sed -e "s|\$$BUILD|$$buildid|g" -e "s|\$$DATASET|$(HONEY_DATASET)|g" -e "s|\$$HONEYKEY|$(HONEY_KEY)|g" main.go > main_new.go; \
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o main main_new.go
	sed -e "s|\$$SBUILD|$$buildid|g" -e "s|\$$SDATASET|$(HONEY_DATASET)|g" -e "s|\$$SHONEYKEY|$(HONEY_KEY)|g" setup.go > setup_new.go; \
    GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o setup setup_new.go
	zip moose.zip main
	zip moose.zip setup
	@aws --region $(REGION) s3 cp moose.zip s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(LAMBDA_PREFIX) --acl public-read
	@aws --region $(REGION) s3 cp moose-integration.yml s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(CFT_PREFIX) --acl public-read
	rm main || true
	rm main_new.go || true
	rm setup || true
	rm setup_new.go || true
	rm moose.zip || true






