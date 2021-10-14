module github.com/yahoojapan/athenz-client-sidecar/v2

go 1.14

require (
	github.com/AthenZ/athenz v1.10.35
	github.com/kpango/fastime v1.0.17
	github.com/kpango/gache v1.2.6
	github.com/kpango/glg v1.6.4
	github.com/kpango/ntokend v1.0.12
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/AthenZ/athenz v1.10.28 => github.com/AthenZ/athenz v1.10.35
