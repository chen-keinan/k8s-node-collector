SHELL := /bin/bash

GOCMD=go
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test


all:
	$(info  "completed running make file for k8s node collector")
fmt:
	@go fmt ./...
tidy:
	$(GOMOD) tidy -v
test:
	$(GOTEST) ./... 

build:
	cd ./cmd/node-collector && go build -o node-collector main.go 

build-docker:
	docker build -t ghcr.io/aquasecurity/node-collector:dev .

.PHONY: install-req fmt lint tidy test imports .
