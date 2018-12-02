FROM golang:1.11-alpine AS base

RUN set -eux \
    && apk --no-cache add ca-certificates \
    && apk --no-cache add --virtual build-dependencies cmake g++ make unzip curl upx git

WORKDIR ${GOPATH}/src/ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar

COPY go.mod .
COPY go.sum .

RUN GO111MODULE=on go mod download

FROM base AS builder

ENV APP_NAME tenant

COPY . .

RUN CGO_ENABLED=1 \
    CGO_CXXFLAGS="-g -Ofast -march=native" \
    CGO_FFLAGS="-g -Ofast -march=native" \
    CGO_LDFLAGS="-g -Ofast -march=native" \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    GO111MODULE=on \
    go build --ldflags '-s -w -linkmode "external" -extldflags "-static -fPIC -m64 -pthread -std=c++11 -lstdc++"' -a -tags "cgo netgo" -installsuffix "cgo netgo" -o "${APP_NAME}" \
    && upx -9 -o "/usr/bin/${APP_NAME}" "${APP_NAME}" \
    && mv config/cybertrust_root_cacert_g2.crt /etc/athenz/ca.crt

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Scratch For Running Environment
FROM scratch
# FROM alpine:latest
LABEL maintainer "yusukato <yusukato@yahoo-corp.jp>"

ENV APP_NAME tenant

# Copy certificates for SSL/TLS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Copy permissions
COPY --from=builder /etc/passwd /etc/passwd
# Copy our static executable
COPY --from=builder /usr/bin/${APP_NAME} /go/bin/${APP_NAME}
# Copy root ca
COPY --from=builder /etc/athenz/ca.crt /etc/athenz/ca.crt

ENTRYPOINT ["/go/bin/tenant"]
