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

deps:
	rm -rf Gopkg.* vendor
	dep init

test:
	go test --race ./...

bpctl-login:
	bpctl auth login --idp-ca-certificate ~/.bp/ca.pem

docker-push:
	sudo docker build --pull=true --file=Dockerfile -t yahoojapan/athenz-client-sidecar:latest .
	sudo docker push yahoojapan/athenz-client-sidecar:latest
