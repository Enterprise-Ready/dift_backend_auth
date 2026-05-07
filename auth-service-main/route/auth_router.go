package route

import (
	adapterhttp "dift_backend_go/auth-service/internal/adapter/inbound/http"
	internalroute "dift_backend_go/auth-service/internal/route"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, auth *adapterhttp.AuthHandler, health *adapterhttp.HealthHandler, verify *adapterhttp.VerificationHandler) {
	internalroute.RegisterAuthRoutes(r, auth, health, verify)
}
