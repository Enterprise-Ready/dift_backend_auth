.PHONY: run build test lint migrate docker-up docker-down clean tidy

# ─── Development ──────────────────────────────────────────────────────────────

run:
	go run ./cmd/server

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/auth-engine ./cmd/server

test:
	go test ./... -v -race -coverprofile=coverage.out

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

# ─── Database ─────────────────────────────────────────────────────────────────

migrate:
	psql "$(DATABASE_DSN)" -f deployments/migrations.sql

migrate-docker:
	docker exec -i auth-postgres psql -U auth -d auth_engine < deployments/migrations.sql

# ─── Docker ───────────────────────────────────────────────────────────────────

docker-build:
	docker build -f deployments/Dockerfile -t auth-engine:latest .

docker-up:
	docker-compose -f deployments/docker-compose.yml up -d

docker-up-dev:
	docker-compose -f deployments/docker-compose.yml --profile dev up -d

docker-down:
	docker-compose -f deployments/docker-compose.yml down

docker-logs:
	docker-compose -f deployments/docker-compose.yml logs -f auth-engine

# ─── Utilities ────────────────────────────────────────────────────────────────

clean:
	rm -rf bin/ coverage.out

gen-secret:
	@openssl rand -base64 32

coverage:
	go tool cover -html=coverage.out
