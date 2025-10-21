module github.com/AthenZ/authorization-proxy/v4

go 1.25.3

replace (
	cloud.google.com/go => cloud.google.com/go v0.123.0
	github.com/AthenZ/athenz-authorizer/v5 => github.com/AthenZ/athenz-authorizer/v5 v5.7.0
	github.com/kpango/gache/v2 => github.com/kpango/gache/v2 v2.1.1
	github.com/kpango/glg => github.com/kpango/glg v1.6.15
	github.com/mwitkow/grpc-proxy => github.com/mwitkow/grpc-proxy v0.0.0-20250813121105-2866842de9a5
	github.com/pkg/errors => github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model => github.com/prometheus/client_model v0.6.2
	golang.org/x/sync => golang.org/x/sync v0.17.0
	google.golang.org/genproto/googleapis/rpc => google.golang.org/genproto/googleapis/rpc v0.0.0-20251007200510-49b9836ed3ff
	google.golang.org/grpc => google.golang.org/grpc v1.76.0
	google.golang.org/protobuf => google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/AthenZ/athenz-authorizer/v5 v5.0.0-00010101000000-000000000000
	github.com/kpango/gache/v2 v2.1.0
	github.com/kpango/glg v1.6.15
	github.com/mwitkow/grpc-proxy v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.4
	github.com/prometheus/client_model v0.6.2
	golang.org/x/sync v0.17.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/AthenZ/athenz v1.12.27 // indirect
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.3 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kpango/fastime v1.1.10 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.1 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.11 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/common v0.67.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/theparanoids/crypki v1.20.9 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.opentelemetry.io/proto/otlp v1.8.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251007200510-49b9836ed3ff // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251002232023-7c0ddcbb5797 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.34.1 // indirect
	k8s.io/client-go v0.34.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
)
