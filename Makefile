GO_VERSION:=$(shell go version)

.PHONY: bench profile clean test

all: install

bench:
	go test -count=5 -run=NONE -bench . -benchmem

profile: clean
	mkdir pprof
	mkdir bench
	go test -count=10 -run=NONE -bench . -benchmem -o pprof/test.bin -cpuprofile pprof/cpu.out -memprofile pprof/mem.out
	go tool pprof --svg pprof/test.bin pprof/mem.out > bench/mem.svg
	go tool pprof --svg pprof/test.bin pprof/cpu.out > bench/cpu.svg

clean:
	rm -rf bench
	rm -rf pprof
	rm -rf ./*.svg
	rm -rf ./*.log

test:
	go test --race ./...

bpctl-login:
	bpctl auth login --idp-ca-certificate ~/.bp/ca.pem

docker-push:
	sudo docker build --pull=true --file=Dockerfile -t cd.docker-registry.corp.yahoo.co.jp:4443/athenz/athenz-tenant-sidecar:latest .
	sudo docker push cd.docker-registry.corp.yahoo.co.jp:4443/athenz/athenz-tenant-sidecar:latest

docker-push-dev:
	sudo docker build --pull=true --file=Dockerfile -t cd.sandbox.docker-registry.corp.yahoo.co.jp:4443/athenz/athenz-tenant-sidecar:latest .
	sudo docker push cd.sandbox.docker-registry.corp.yahoo.co.jp:4443/athenz/athenz-tenant-sidecar:latest
