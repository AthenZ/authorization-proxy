module github.com/AthenZ/authorization-proxy/v4

go 1.20

replace (
	cloud.google.com/go => cloud.google.com/go v0.112.2
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/golang/protobuf => github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp => github.com/google/go-cmp v0.6.0
	github.com/google/pprof => github.com/google/pprof v0.0.0-20240402174815-29b9bb013b0f
	github.com/mwitkow/grpc-proxy => github.com/mwitkow/grpc-proxy v0.0.0-20181017164139-0f1106ef9c76
	golang.org/x/crypto => golang.org/x/crypto v0.22.0
	golang.org/x/exp => golang.org/x/exp v0.0.0-20240404231335-c0f41cb1a7a0
	golang.org/x/image => golang.org/x/image v0.15.0
	golang.org/x/lint => golang.org/x/lint v0.0.0-20210508222113-6edffad5e616
	golang.org/x/mobile => golang.org/x/mobile v0.0.0-20240404231514-09dbf07665ed
	golang.org/x/mod => golang.org/x/mod v0.17.0
	golang.org/x/net => golang.org/x/net v0.24.0
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.19.0
	golang.org/x/sync => golang.org/x/sync v0.7.0
	golang.org/x/sys => golang.org/x/sys v0.19.0
	golang.org/x/term => golang.org/x/term v0.19.0
	golang.org/x/text => golang.org/x/text v0.14.0
	golang.org/x/time => golang.org/x/time v0.5.0
	golang.org/x/tools => golang.org/x/tools v0.20.0
	golang.org/x/xerrors => golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028
	google.golang.org/api => google.golang.org/api v0.172.0
	google.golang.org/appengine => google.golang.org/appengine v1.6.8
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20240401170217-c3f982113cda
	google.golang.org/grpc => google.golang.org/grpc v1.63.0
	google.golang.org/protobuf => google.golang.org/protobuf v1.33.0
)

require (
	github.com/AthenZ/athenz-authorizer/v5 v5.5.2
	github.com/kpango/glg v1.6.15
	github.com/mwitkow/grpc-proxy v0.0.0-20181017164139-0f1106ef9c76
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.7.0
	google.golang.org/grpc v1.58.2
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/AthenZ/athenz v1.11.43 // indirect
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/kpango/fastime v1.1.9 // indirect
	github.com/kpango/gache v1.2.8 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx v1.2.26 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
)
