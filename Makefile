# GO_VERSION:=$(shell go version)

# .PHONY: all clean bench bench-all profile lint test contributors update install
.PHONY: deps

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

# test: clean init
# 	GO111MODULE=on go test --race -v ./...

# contributors:
# 	git log --format='%aN <%aE>' | sort -fu > CONTRIBUTORS

# docker-push:
# 	sudo docker build --pull=true --file=Dockerfile -t docker.io/athenz/authorization-proxy:latest .
# 	sudo docker push docker.io/athenz/authorization-proxy:latest

# coverage:
# 	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
# 	go tool cover -html=coverage.out -o coverage.html
# 	rm -f coverage.out

check-license-header:
	# go install github.com/apache/skywalking-eyes/cmd/license-eye@latest
	license-eye -c .licenserc.yaml header check
	# license-eye -c .licenserc.yaml header fix
