module github.com/AthenZ/authorization-proxy/v4

go 1.16

require (
	github.com/AthenZ/athenz-authorizer/v5 v5.3.2
	github.com/kpango/glg v1.6.10
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
)

replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.3

replace golang.org/x/text v0.3.2 => golang.org/x/text v0.3.3
