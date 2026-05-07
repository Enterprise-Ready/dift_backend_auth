package http

import (
	"net/http"

	"dift_backend_go/auth-service/internal/dto"
	serviceport "dift_backend_go/auth-service/internal/interface/service/auth"
	wrapper "dift_backend_go/auth-service/pkg/authguard"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	command serviceport.CommandService
	query   serviceport.QueryService
}

func NewAuthHandler(command serviceport.CommandService, query serviceport.QueryService) *AuthHandler {
	return &AuthHandler{command: command, query: query}
}

func (h *AuthHandler) RegisterEmail(c *gin.Context) {
	var req dto.RegisterEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.Name = wrapper.CleanString(req.Name)
	req.Email = wrapper.CleanEmail(req.Email)
	if err := wrapper.Required("name", req.Name); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := wrapper.MaxLen("name", req.Name, 100); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := wrapper.ValidateEmail(req.Email); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := wrapper.Required("password", req.Password); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.command.RegisterEmail(c.Request.Context(), req)
	if err != nil {
		writeError(c, http.StatusBadRequest, "register_failed", err.Error())
		return
	}
	c.JSON(http.StatusCreated, res)
}

func (h *AuthHandler) LoginEmail(c *gin.Context) {
	var req dto.LoginEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.Email = wrapper.CleanEmail(req.Email)
	if err := wrapper.ValidateEmail(req.Email); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := wrapper.Required("password", req.Password); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.command.LoginEmail(c.Request.Context(), req)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "auth_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.RefreshToken = wrapper.CleanString(req.RefreshToken)
	if err := wrapper.Required("refresh_token", req.RefreshToken); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.command.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "refresh_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.RefreshToken = wrapper.CleanString(req.RefreshToken)
	if err := wrapper.Required("refresh_token", req.RefreshToken); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := h.command.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		writeError(c, http.StatusBadRequest, "logout_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

func (h *AuthHandler) Me(c *gin.Context) {
	token, ok := c.Get("access_token")
	if !ok {
		writeError(c, http.StatusUnauthorized, "unauthorized", "missing access token")
		return
	}
	profile, err := h.query.Me(c.Request.Context(), token.(string))
	if err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	c.JSON(http.StatusOK, profile)
}
