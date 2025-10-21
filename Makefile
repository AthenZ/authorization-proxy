# GO_VERSION:=$(shell go version)

# .PHONY: all clean bench bench-all profile lint test contributors update install
.PHONY: deps test coverage


ROOTDIR = $(eval ROOTDIR := $(shell git rev-parse --show-toplevel))$(ROOTDIR)
GITHUB_ACCESS_TOKEN = $(eval GITHUB_ACCESS_TOKEN := $(shell pass github.api.ro.token))$(GITHUB_ACCESS_TOKEN)
GITHUB_SHA = $(eval GITHUB_SHA := $(shell git rev-parse HEAD))$(GITHUB_SHA)
GITHUB_URL = https://github.com/AthenZ/authorization-proxy
EMAIL = cncf-athenz-maintainers@lists.cncf.io

DOCKERFILE = $(ROOTDIR)/Dockerfile
DOCKER_EXTRA_OPTS = ""
DOCKER_BUILDER_NAME = "athenz-builder"
DOCKER_BUILDER_DRIVER = "docker-container"
DOCKER_BUILDER_PLATFORM = "linux/amd64"
DOCKER_IMAGE_REPO = AthenZ
DOCKER_IMAGE_NAME = authorization-proxy

VERSION = latest

GOPATH := $(eval GOPATH := $(shell go env GOPATH))$(GOPATH)
GOLINES_MAX_WIDTH     ?= 200

# all: clean install lint test bench

# clean:
# 	go clean -modcache
# 	rm -rf ./*.log
# 	rm -rf ./*.svg
# 	rm -rf ./go.mod
# 	rm -rf ./go.sum
# 	rm -rf bench
# 	rm -rf pprof
# 	rm -rf vendor
# 	cp go.mod.default go.mod

# bench: clean init
# 	go test -count=5 -run=NONE -bench . -benchmem

# init:
# 	GO111MODULE=on go mod init
# 	GO111MODULE=on go mod vendor
# 	sleep 3

deps:
	rm -f ./go.sum
	cp ./go.mod.default ./go.mod
	GO111MODULE=on go mod tidy

# lint:
# 	gometalinter --enable-all . | rg -v comment

test:
	go test -v -race ./...

coverage:
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm -f coverage.out

# contributors:
# 	git log --format='%aN <%aE>' | sort -fu > CONTRIBUTORS

# docker-push:
# 	sudo docker build --pull=true --file=Dockerfile -t docker.io/athenz/authorization-proxy:latest .
# 	sudo docker push docker.io/athenz/authorization-proxy:latest

check-license-header:
	# go install github.com/apache/skywalking-eyes/cmd/license-eye@latest
	license-eye -c .licenserc.yaml header check
	# license-eye -c .licenserc.yaml header fix

docker_build:
	@make DOCKER_BUILDER_NAME=$(DOCKER_BUILDER_NAME) create_buildx
	$(eval TMP_DIR := $(shell mktemp -d))
	@echo $(GITHUB_ACCESS_TOKEN) > $(TMP_DIR)/gat
	@chmod 600 $(TMP_DIR)/gat
	DOCKER_BUILDKIT=1 docker buildx build \
		--allow "network.host" \
		--build-arg BUILDKIT_MULTI_PLATFORM=1 \
		--build-arg EMAIL="$(EMAIL)" \
		--builder "$(DOCKER_BUILDER_NAME)" \
		--label org.opencontainers.image.revision="$(GITHUB_SHA)" \
		--label org.opencontainers.image.source="$(GITHUB_URL)" \
		--label org.opencontainers.image.title="$(DOCKER_IMAGE_REPO)/$(DOCKER_IMAGE_NAME)" \
		--label org.opencontainers.image.url="$(GITHUB_URL)" \
		--label org.opencontainers.image.version="$(VERSION)" \
		--memory 32G \
		--memory-swap 32G \
		--network=host \
		--output type=registry,oci-mediatypes=true,compression=zstd,compression-level=5,force-compression=true,push=true \
		--platform $(DOCKER_BUILDER_PLATFORM) \
		--attest type=sbom,generator=docker/buildkit-syft-scanner:edge \
		--provenance=mode=max \
		-t "$(DOCKER_IMAGE_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION)" \
		-f $(DOCKERFILE) .
	docker buildx rm --force "$(DOCKER_BUILDER_NAME)"
	@rm -rf $(TMP_DIR)


init_buildx:
	docker run \
		--network=host \
		--privileged \
		--rm tonistiigi/binfmt:master \
		--install $(DOCKER_BUILDER_PLATFORM)

create_buildx:
	-docker buildx rm --force $(DOCKER_BUILDER_NAME)
	docker buildx create --use \
		--name $(DOCKER_BUILDER_NAME) \
		--driver $(DOCKER_BUILDER_DRIVER) \
		--driver-opt=image=moby/buildkit:master \
		--driver-opt=network=host \
		--buildkitd-flags="--oci-worker-gc=false --oci-worker-snapshotter=stargz" \
		--platform $(DOCKER_BUILDER_PLATFORM) \
		--bootstrap
	# make add_nodes
	docker buildx ls
	docker buildx inspect --bootstrap $(DOCKER_BUILDER_NAME)
	sudo chown -R $(USER):$(GROUP_ID) "$(HOME)/.docker"

remove_buildx:
	-docker buildx rm --force --all-inactive
	sudo rm -rf $(HOME)/.docker/buildx
	docker buildx ls

do_build:
	@make DOCKERFILE="$(ROOTDIR)/Dockerfile" NAME="$(NAME)" DOCKER_BUILDER_NAME="$(DOCKER_BUILDER_NAME)-$(NAME)" docker_build

build: \
	remove_buildx \
	init_buildx \
	create_buildx
	@make NAME="authorization-proxy" do_build
	@make remove_buildx

format:
	find ./ -type d -name .git -prune -o -type f -regex '.*[^\.pb]\.go' -print | xargs $(GOPATH)/bin/golines -w -m $(GOLINES_MAX_WIDTH)
	find ./ -type d -name .git -prune -o -type f -regex '.*[^\.pb]\.go' -print | xargs $(GOPATH)/bin/gofumpt -w
	find ./ -type d -name .git -prune -o -type f -regex '.*[^\.pb]\.go' -print | xargs $(GOPATH)/bin/strictgoimports -w
	find ./ -type d -name .git -prune -o -type f -regex '.*\.go' -print | xargs $(GOPATH)/bin/goimports -w
