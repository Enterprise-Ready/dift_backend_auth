//go:build legacy
// +build legacy

package face

import (
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"strings"
	"sync"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Descriptor ───────────────────────────────────────────────────────────────

type Descriptor [128]float32

type EnrollmentStore interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*models.FaceEnrollment, error)
	Save(ctx context.Context, enrollment *models.FaceEnrollment) error
	Deactivate(ctx context.Context, userID uuid.UUID) error
}

// ─── Service ──────────────────────────────────────────────────────────────────

type Service struct {
	cfg   *config.FaceConfig
	store EnrollmentStore
	log   *zap.Logger
	mu    sync.RWMutex
}

func NewService(cfg *config.FaceConfig, store EnrollmentStore, log *zap.Logger) *Service {
	return &Service{cfg: cfg, store: store, log: log}
}

// ─── Enroll ───────────────────────────────────────────────────────────────────

func (s *Service) Enroll(ctx context.Context, userID uuid.UUID, imageBase64 string) error {
	imgBytes, err := decodeBase64Image(imageBase64)
	if err != nil {
		return fmt.Errorf("decode image: %w", err)
	}

	descriptor, confidence, err := s.extractDescriptor(imgBytes)
	if err != nil {
		return fmt.Errorf("extract descriptor: %w", err)
	}

	if confidence < s.cfg.MinConfidence {
		return ErrLowConfidence
	}

	// Deactivate old enrollment
	_ = s.store.Deactivate(ctx, userID)

	enrollment := &models.FaceEnrollment{
		UserID:     userID,
		Descriptor: descriptor,
		Confidence: confidence,
		IsActive:   true,
	}
	if err := s.store.Save(ctx, enrollment); err != nil {
		return fmt.Errorf("save enrollment: %w", err)
	}

	s.log.Info("face enrolled", zap.String("user_id", userID.String()), zap.Float32("confidence", confidence))
	return nil
}

// ─── Verify ───────────────────────────────────────────────────────────────────

func (s *Service) Verify(ctx context.Context, userID uuid.UUID, imageBase64 string) (bool, float32, error) {
	enrollment, err := s.store.GetByUserID(ctx, userID)
	if err != nil {
		return false, 0, ErrNotEnrolled
	}

	imgBytes, err := decodeBase64Image(imageBase64)
	if err != nil {
		return false, 0, fmt.Errorf("decode image: %w", err)
	}

	descriptor, confidence, err := s.extractDescriptor(imgBytes)
	if err != nil {
		return false, 0, fmt.Errorf("extract descriptor: %w", err)
	}

	distance := euclideanDistance(enrollment.Descriptor, descriptor)
	similarity := 1 - (distance / 2) // normalize to [0,1]

	matched := distance <= float32(s.cfg.Tolerance)

	s.log.Info("face verify",
		zap.String("user_id", userID.String()),
		zap.Float32("distance", distance),
		zap.Float32("similarity", similarity),
		zap.Bool("matched", matched),
		zap.Float32("confidence", confidence),
	)

	return matched, similarity, nil
}

// ─── Liveness ─────────────────────────────────────────────────────────────────

func (s *Service) CheckLiveness(imageBase64 string) (bool, float32, error) {
	if !s.cfg.LivenessEnabled {
		return true, 1.0, nil
	}
	// Production: integrate with a liveness detection API
	// Options: AWS Rekognition, Azure Face API, FaceTec, iProov
	// Stub returns true – replace with real implementation
	return true, 0.95, nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Service) extractDescriptor(imgBytes []byte) ([]float32, float32, error) {
	// Production: use go-face (dlib) or call an external API
	// go-face example:
	//   rec, _ := face.NewRecognizer(s.cfg.ModelPath)
	//   faces, _ := rec.Recognize(imgBytes)
	//   if len(faces) != 1 { return ErrNoFace / ErrMultipleFaces }
	//   return faces[0].Descriptor[:], confidence, nil

	// Stub returns synthetic descriptor for compilation
	desc := make([]float32, 128)
	return desc, 0.99, nil
}

func decodeBase64Image(b64 string) ([]byte, error) {
	// Strip data URI prefix if present
	if idx := strings.Index(b64, ","); idx != -1 {
		b64 = b64[idx+1:]
	}
	return base64.StdEncoding.DecodeString(b64)
}

func euclideanDistance(a, b []float32) float32 {
	if len(a) != len(b) {
		return math.MaxFloat32
	}
	var sum float32
	for i := range a {
		d := a[i] - b[i]
		sum += d * d
	}
	return float32(math.Sqrt(float64(sum)))
}

func validateImageDimensions(data []byte, maxSize int) error {
	cfg, _, err := image.DecodeConfig(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("invalid image")
	}
	if cfg.Width > maxSize || cfg.Height > maxSize {
		return fmt.Errorf("image too large: max %dpx", maxSize)
	}
	return nil
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrNotEnrolled   = fmt.Errorf("face not enrolled")
	ErrLowConfidence = fmt.Errorf("face confidence too low")
	ErrNoFace        = fmt.Errorf("no face detected in image")
	ErrMultipleFaces = fmt.Errorf("multiple faces detected")
	ErrLivenessCheck = fmt.Errorf("liveness check failed")
)
