IMAGE ?= ghcr.io/hushsecurity/hush-exporter
TAG ?= dev

.PHONY: build test lint image

build:
	go build -o bin/hush-exporter ./cmd/hush-exporter

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

image:
	docker build -t $(IMAGE):$(TAG) .
