package http

import (
	"net/http"
	"strconv"

	authservice "dift_backend_go/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

type VerificationHandler struct {
	svc *authservice.VerificationService
}

func NewVerificationHandler(svc *authservice.VerificationService) *VerificationHandler {
	return &VerificationHandler{svc: svc}
}

func (h *VerificationHandler) CreateOTP(c *gin.Context) {
	var req struct {
		UserID  string `json:"user_id"`
		Channel string `json:"channel"`
		Target  string `json:"target"`
		TTL     int    `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid payload")
		return
	}
	id, code, err := h.svc.CreateOTP(c.Request.Context(), req.UserID, req.Channel, req.Target, req.TTL)
	if err != nil {
		writeError(c, http.StatusBadRequest, "otp_create_failed", err.Error())
		return
	}
	c.JSON(http.StatusCreated, gin.H{"challenge_id": id, "dev_code": code})
}

func (h *VerificationHandler) VerifyOTP(c *gin.Context) {
	var req struct {
		UserID      string `json:"user_id"`
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid payload")
		return
	}
	ok, err := h.svc.VerifyOTP(c.Request.Context(), req.UserID, req.ChallengeID, req.Code)
	if err != nil {
		writeError(c, http.StatusBadRequest, "otp_verify_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": ok})
}

func (h *VerificationHandler) VerifyFace(c *gin.Context) {
	var req struct {
		UserID        string `json:"user_id"`
		LivenessToken string `json:"liveness_token"`
		SelfieRef     string `json:"selfie_ref"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid payload")
		return
	}
	approved, score, err := h.svc.VerifyFace(c.Request.Context(), req.UserID, req.LivenessToken, req.SelfieRef)
	if err != nil {
		writeError(c, http.StatusBadRequest, "face_verify_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"approved": approved, "score": score})
}

func (h *VerificationHandler) EvaluateRisk(c *gin.Context) {
	var req struct {
		UserID   string `json:"user_id"`
		Action   string `json:"action"`
		IP       string `json:"ip"`
		DeviceID string `json:"device_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid payload")
		return
	}
	score, level, err := h.svc.EvaluateRisk(c.Request.Context(), req.UserID, req.Action, req.IP, req.DeviceID)
	if err != nil {
		writeError(c, http.StatusBadRequest, "risk_evaluate_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"score": score, "level": level})
}

func (h *VerificationHandler) ListAudit(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	c.JSON(http.StatusOK, gin.H{"items": h.svc.ListAudit(c.Request.Context(), limit)})
}
