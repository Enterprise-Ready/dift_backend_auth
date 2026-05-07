module github.com/enterprise/auth-engine

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/redis/go-redis/v9 v9.5.1
	github.com/lib/pq v1.10.9
	github.com/jmoiron/sqlx v1.3.5
	golang.org/x/crypto v0.22.0
	github.com/pquerna/otp v1.4.0
	github.com/sendgrid/sendgrid-go v3.14.0+incompatible
	github.com/aws/aws-sdk-go-v2 v1.26.1
	github.com/aws/aws-sdk-go-v2/service/sns v1.29.1
	github.com/twilio/twilio-go v1.20.1
	firebase.google.com/go/v4 v4.14.0
	github.com/supabase-community/supabase-go v0.0.4
	golang.org/x/oauth2 v0.19.0
	github.com/go-playground/validator/v10 v10.20.0
	go.uber.org/zap v1.27.0
	github.com/spf13/viper v1.18.2
	github.com/prometheus/client_golang v1.19.0
	go.opentelemetry.io/otel v1.25.0
	go.opentelemetry.io/otel/trace v1.25.0
	github.com/gin-contrib/cors v1.7.1
	github.com/ulule/limiter/v3 v3.11.2
	github.com/Kagami/go-face v0.0.0-20210630145111-0803814fa753
	gorm.io/gorm v1.25.9
	gorm.io/driver/postgres v1.5.7
	github.com/hibiken/asynq v0.24.1
	golang.org/x/time v0.5.0
)
