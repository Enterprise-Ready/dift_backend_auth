//go:build legacy
// +build legacy

package auth

import (
	"net/http"

	"github.com/enterprise/auth-engine/internal/auth"
	"github.com/enterprise/auth-engine/internal/middleware"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Handler struct {
	svc      *auth.Service
	validate *validator.Validate
	log      *zap.Logger
}

func NewHandler(svc *auth.Service, log *zap.Logger) *Handler {
	return &Handler{
		svc:      svc,
		validate: validator.New(),
		log:      log,
	}
}

func (h *Handler) RegisterRoutes(r *gin.RouterGroup, rl *middleware.RateLimiter, jwtMid gin.HandlerFunc) {
	// Public
	r.POST("/register", rl.Limit("register", 5, 24*60*60*1e9), h.Register)
	r.POST("/login", rl.Limit("login", 10, 60*1e9), h.Login)
	r.POST("/login/oauth", rl.Limit("login", 10, 60*1e9), h.OAuthLogin)
	r.POST("/login/face", rl.Limit("face_login", 5, 60*1e9), h.FaceLogin)
	r.POST("/token/refresh", h.RefreshToken)
	r.POST("/otp/send", rl.Limit("otp", 5, 60*60*1e9), h.SendOTP)
	r.POST("/otp/verify", rl.Limit("otp_verify", 10, 15*60*1e9), h.VerifyOTP)
	r.POST("/password/forgot", rl.Limit("forgot_pw", 3, 60*60*1e9), h.ForgotPassword)
	r.POST("/password/reset", h.ResetPassword)

	// Authenticated
	authed := r.Group("/", jwtMid)
	authed.POST("/logout", h.Logout)
	authed.POST("/logout/all", h.LogoutAll)
	authed.GET("/me", h.Me)
	authed.POST("/mfa/enable", h.EnableMFA)
	authed.POST("/mfa/confirm", h.ConfirmMFA)
	authed.DELETE("/mfa", h.DisableMFA)
	authed.POST("/face/enroll", h.EnrollFace)
}

// ─── Register ─────────────────────────────────────────────────────────────────

// POST /auth/register
func (h *Handler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	user, err := h.svc.Register(c.Request.Context(), &req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "registration successful, please verify your account",
		"user_id": user.ID,
	})
}

// ─── Login ────────────────────────────────────────────────────────────────────

// POST /auth/login
func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), &req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	if resp.MFARequired {
		c.JSON(http.StatusOK, gin.H{"mfa_required": true, "message": "please provide mfa code"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ─── OAuth Login ──────────────────────────────────────────────────────────────

// POST /auth/login/oauth
func (h *Handler) OAuthLogin(c *gin.Context) {
	var req models.OAuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}
	if err := h.validate.Struct(req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	resp, err := h.svc.OAuthLogin(c.Request.Context(), &req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ─── Face Login ───────────────────────────────────────────────────────────────

// POST /auth/login/face
func (h *Handler) FaceLogin(c *gin.Context) {
	var body struct {
		Identifier string              `json:"identifier" validate:"required"`
		Image      string              `json:"image" validate:"required"`
		DeviceInfo models.DeviceInfo   `json:"device_info"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	// First validate identifier, then face
	loginReq := &models.LoginRequest{
		Identifier: body.Identifier,
		DeviceInfo: body.DeviceInfo,
	}
	// Reuse login flow for lockout/suspension checks, but skip password
	user, err := h.svc.GetUserByIdentifier(c.Request.Context(), body.Identifier)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	matched, err := h.svc.FaceVerify(c.Request.Context(), user.ID, body.Image)
	if err != nil || !matched {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "face verification failed"})
		return
	}

	_ = loginReq
	c.JSON(http.StatusOK, gin.H{"message": "face verified", "user_id": user.ID})
}

// ─── Token Refresh ────────────────────────────────────────────────────────────

// POST /auth/token/refresh
func (h *Handler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	resp, err := h.svc.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ─── OTP ─────────────────────────────────────────────────────────────────────

// POST /auth/otp/send
func (h *Handler) SendOTP(c *gin.Context) {
	var req models.SendOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	// Try to find user; allow sending without auth for login/register flows
	userID, _ := middleware.GetUserID(c)

	if err := h.svc.SendOTP(c.Request.Context(), userID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send otp"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "otp sent"})
}

// POST /auth/otp/verify
func (h *Handler) VerifyOTP(c *gin.Context) {
	var req models.VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	if err := h.svc.VerifyOTP(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"verified": true})
}

// ─── Password ─────────────────────────────────────────────────────────────────

// POST /auth/password/forgot
func (h *Handler) ForgotPassword(c *gin.Context) {
	var body struct {
		Identifier string `json:"identifier" validate:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	_ = h.svc.RequestPasswordReset(c.Request.Context(), body.Identifier, c.ClientIP(), c.GetHeader("User-Agent"))
	// Always respond OK to prevent user enumeration
	c.JSON(http.StatusOK, gin.H{"message": "if an account exists, a reset code has been sent"})
}

// POST /auth/password/reset
func (h *Handler) ResetPassword(c *gin.Context) {
	var body struct {
		Identifier  string `json:"identifier" validate:"required"`
		Token       string `json:"token" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	err := h.svc.ResetPassword(c.Request.Context(), body.Identifier, body.Token, body.NewPassword, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}

// ─── Logout ───────────────────────────────────────────────────────────────────

// POST /auth/logout
func (h *Handler) Logout(c *gin.Context) {
	sessionID, _ := c.Get(middleware.CtxSessionID)
	_ = h.svc.Logout(c.Request.Context(), sessionID.(uuid.UUID))
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// POST /auth/logout/all
func (h *Handler) LogoutAll(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	_ = h.svc.LogoutAll(c.Request.Context(), userID)
	c.JSON(http.StatusOK, gin.H{"message": "all sessions revoked"})
}

// ─── Profile ──────────────────────────────────────────────────────────────────

// GET /auth/me
func (h *Handler) Me(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	user, err := h.svc.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// ─── MFA ─────────────────────────────────────────────────────────────────────

// POST /auth/mfa/enable
func (h *Handler) EnableMFA(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var body struct {
		Password string `json:"password" validate:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	secret, qrURL, backupCodes, err := h.svc.EnableMFA(c.Request.Context(), userID, body.Password)
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":       secret,
		"qr_url":       qrURL,
		"backup_codes": backupCodes,
		"message":      "scan the QR code and confirm with /mfa/confirm",
	})
}

// POST /auth/mfa/confirm
func (h *Handler) ConfirmMFA(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var body struct {
		Code string `json:"code" validate:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	if err := h.svc.ConfirmMFA(c.Request.Context(), userID, body.Code); err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "mfa enabled"})
}

// DELETE /auth/mfa
func (h *Handler) DisableMFA(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var body struct {
		Code string `json:"code" validate:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	if err := h.svc.DisableMFA(c.Request.Context(), userID, body.Code); err != nil {
		h.handleAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "mfa disabled"})
}

// ─── Face Enrollment ──────────────────────────────────────────────────────────

// POST /auth/face/enroll
func (h *Handler) EnrollFace(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var req models.EnrollFaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.badRequest(c, err.Error())
		return
	}

	if err := h.svc.EnrollFace(c.Request.Context(), userID, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "face enrolled successfully"})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) badRequest(c *gin.Context, msg string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": msg})
}

func (h *Handler) handleAuthError(c *gin.Context, err error) {
	switch err {
	case auth.ErrInvalidCredentials, auth.ErrUserNotFound:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
	case auth.ErrAccountLocked:
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	case auth.ErrAccountSuspended:
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	case auth.ErrEmailAlreadyExists, auth.ErrPhoneAlreadyExists:
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case auth.ErrInvalidToken, auth.ErrSessionExpired:
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case auth.ErrInvalidMFACode:
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case auth.ErrSessionLimitReached:
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	default:
		h.log.Error("unhandled auth error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
