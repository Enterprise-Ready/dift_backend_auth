package http

import (
	wrapper "dift_backend_go/auth-service/pkg/authguard"
	"github.com/gin-gonic/gin"
)

func writeError(c *gin.Context, status int, code, msg string) {
	be := wrapper.NewBaseError(code, status, msg)
	payload := wrapper.APIResponse(be)
	if payload.Error != nil {
		payload.Error.Meta = map[string]interface{}{"request_id": c.GetString("request_id")}
	}
	c.AbortWithStatusJSON(wrapper.HTTPStatus(be), payload)
}
