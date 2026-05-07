# auth-service structure

## Layers
- `cmd/main.go`: composition root
- `config/`: YAML + env configuration
- `route/`: top-level route registration
- `internal/adapter`: inbound/outbound adapters (HTTP + integration client)
- `internal/interface`: application contracts
- `internal/service`: auth business use-cases
- `internal/integration`: infrastructure (HTTP server)
- `proto/`: protobuf contracts for service-to-service

## Runtime flow
1. HTTP request enters adapter
2. adapter calls service port
3. service calls identity gRPC client
4. response returns with standardized error/request-id
