GO_VERSION:=$(shell go version)

.PHONY: all clean bench bench-all profile lint test contributors update install

all: clean install lint test bench

clean:
	go clean ./...
	go clean -modcache
	rm -rf ./*.log
	rm -rf ./*.svg
	rm -rf ./go.mod
	rm -rf ./go.sum
	rm -rf bench
	rm -rf pprof
	rm -rf vendor


bench: clean init
	go test -count=5 -run=NONE -bench . -benchmem

init:
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	sleep 3

deps: clean
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	rm -rf vendor

lint:
	gometalinter --enable-all . | rg -v comment

test: clean init
	GO111MODULE=on go test --race -v ./...

contributors:
	git log --format='%aN <%aE>' | sort -fu > CONTRIBUTORS

coverage:
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm -f coverage.outdocker-push:
	sudo docker build --pull=true --file=Dockerfile -t yahoojapan/athenz-client-sidecar:latest .
	sudo docker push yahoojapan/athenz-client-sidecar:latest

