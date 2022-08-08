module github.com/yahoojapan/athenz-client-sidecar/v2

go 1.18

require (
	github.com/AthenZ/athenz v1.11.5
	github.com/kpango/fastime v1.1.4
	github.com/kpango/gache v1.2.8
	github.com/kpango/glg v1.6.11
	github.com/kpango/ntokend v1.0.12
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/goccy/go-json v0.9.10 // indirect
	github.com/klauspost/cpuid/v2 v2.1.0 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f // indirect
)

replace github.com/AthenZ/athenz v1.10.28 => github.com/AthenZ/athenz v1.11.5
