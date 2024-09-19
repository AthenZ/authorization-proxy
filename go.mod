module github.com/AthenZ/authorization-proxy/v4

go 1.23.1

replace (
	cloud.google.com/go => cloud.google.com/go v0.112.2
	github.com/golang/mock => github.com/golang/mock v1.6.0
	github.com/golang/protobuf => github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp => github.com/google/go-cmp v0.6.0
	github.com/google/pprof => github.com/google/pprof v0.0.0-20240409012703-83162a5b38cd
	github.com/mwitkow/grpc-proxy => github.com/mwitkow/grpc-proxy v0.0.0-20181017164139-0f1106ef9c76
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v1.19.1
	github.com/prometheus/common => github.com/prometheus/common v0.48.0
	golang.org/x/crypto => golang.org/x/crypto v0.22.0
	golang.org/x/exp => golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8
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
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20240412170617-26222e5d3d56
	google.golang.org/grpc => google.golang.org/grpc v1.63.2
	google.golang.org/protobuf => google.golang.org/protobuf v1.33.0
)

require (
	github.com/AthenZ/athenz-authorizer/v5 v5.6.0
	github.com/kpango/glg v1.6.15
	github.com/mwitkow/grpc-proxy v0.0.0-20181017164139-0f1106ef9c76
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.18.0
	github.com/prometheus/client_model v0.5.0
	golang.org/x/sync v0.8.0
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/AthenZ/athenz v1.11.63 // indirect
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/kpango/fastime v1.1.9 // indirect
	github.com/kpango/gache/v2 v2.0.11 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx v1.2.30 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240708141625-4ad9e859172b // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.30.3 // indirect
	k8s.io/client-go v0.30.3 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)
