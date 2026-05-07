module github.com/diftapp/identity-platform/access-control-service

go 1.25.0

require (
	github.com/go-chi/chi/v5 v5.0.12
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.5.5
	github.com/nats-io/nats.go v1.37.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

require github.com/PlatformCore/middleware v0.0.0

require github.com/PlatformCore/engine-core/runtime v0.0.0

require github.com/PlatformCore/engine-core/messaging v0.0.0

require github.com/PlatformCore/engine-core/observability v0.0.0

require github.com/PlatformCore/engine-core/resilience v0.0.0

replace github.com/PlatformCore/middleware => ../middleware

replace github.com/PlatformCore/engine-core/runtime => ../engine-core/runtime

replace github.com/PlatformCore/engine-core/messaging => ../engine-core/messaging

replace github.com/PlatformCore/engine-core/observability => ../engine-core/observability

replace github.com/PlatformCore/engine-core/resilience => ../engine-core/resilience

require github.com/PlatformCore/engine-core/transport v0.0.0

require github.com/PlatformCore/engine-core/security v0.0.0

require github.com/PlatformCore/engine-core/validation v0.0.0

require github.com/PlatformCore/engine-core/tenant v0.0.0

require (
	github.com/PlatformCore/engine-core/plugins v0.0.0
	google.golang.org/grpc v1.80.0
)

replace github.com/PlatformCore/engine-core/transport => ../engine-core/transport

replace github.com/PlatformCore/engine-core/security => ../engine-core/security

replace github.com/PlatformCore/engine-core/validation => ../engine-core/validation

replace github.com/PlatformCore/engine-core/tenant => ../engine-core/tenant

replace github.com/PlatformCore/engine-core/plugins => ../engine-core/plugins
