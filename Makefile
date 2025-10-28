.PHONY: all deps generate build run clean docker-build docker-run docker-shell docker-stop docker-clean docker-restart

BIN_DIR := bin
BIN := $(BIN_DIR)/ebpfw

# Docker 설정
DOCKER_IMAGE := ebpfw-test
DOCKER_TAG := latest
DOCKER_IMAGE_FULL := $(DOCKER_IMAGE):$(DOCKER_TAG)
CONTAINER_NAME := ebpfw-test

all: build

deps:
	@go mod tidy
	@go mod download
	@go install github.com/cilium/ebpf/cmd/bpf2go@latest

generate: deps
	@go generate ./...

build: generate
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN) ./main.go

run:
	@sudo ./$(BIN)

clean:
	@rm -rf $(BIN_DIR)
	@rm -f internal/bpf/*_bpfel.go
	@rm -f internal/bpf/*_bpfeb.go
	@rm -f internal/bpf/*_bpfel.o
	@rm -f internal/bpf/*_bpfeb.o

docker-build: build
	@docker build -f test/Dockerfile -t $(DOCKER_IMAGE_FULL) .

docker-run: docker-build
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@docker run -d \
		--name $(CONTAINER_NAME) \
		--privileged \
		-v /sys/fs/bpf:/sys/fs/bpf:rw \
		-p 8080:8080 \
		-p 9090:9090 \
		$(DOCKER_IMAGE_FULL) \
		tail -f /dev/null

docker-shell:
	@docker exec -it $(CONTAINER_NAME) /bin/bash

docker-stop:
	@docker stop $(CONTAINER_NAME)

docker-clean: docker-stop
	@docker rm $(CONTAINER_NAME)
	@docker rmi $(DOCKER_IMAGE_FULL) 2>/dev/null || true

docker-restart: docker-stop docker-run