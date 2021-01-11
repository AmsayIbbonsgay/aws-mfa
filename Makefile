OUTPUT_FILE := aws-mfa


.PHONY: build 
build:
	go build -o ${OUTPUT_FILE}