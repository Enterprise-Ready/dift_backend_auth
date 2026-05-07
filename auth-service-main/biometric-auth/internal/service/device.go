package service

import (
	"errors"
	"fmt"
	"time"

	"biometric-auth/internal/domain"
	"biometric-auth/internal/repository"
)

var (
	ErrDeviceRevoked      = errors.New("device has been revoked")
	ErrDeviceBlocked      = errors.New("device is blocked")
	ErrTooManyDevices     = errors.New("maximum devices per user reached")
	ErrDeviceOwnership    = errors.New("device does not belong to user")
)

type EnableBiometricParams struct {
	PublicKey       string
	KeyID           string
	KeyAlgo         string
	BiometricType   domain.BiometricType
	AttestationData string
	IsRooted        bool
	IsJailbroken    bool
}

type DeviceService struct {
	deviceRepo repository.DeviceRepository
	auditSvc   *AuditService
	cryptoSvc  *CryptoService
}

func NewDeviceService(
	deviceRepo repository.DeviceRepository,
	auditSvc *AuditService,
	cryptoSvc *CryptoService,
) *DeviceService {
	return &DeviceService{deviceRepo: deviceRepo, auditSvc: auditSvc, cryptoSvc: cryptoSvc}
}

// RegisterDevice registers or updates a device for a user.
func (s *DeviceService) RegisterDevice(userID string, d *domain.Device) (*domain.Device, error) {
	d.UserID = userID
	d.DeviceFingerprint = s.cryptoSvc.HashFingerprint(d.DeviceFingerprint)
	d.Status = domain.DeviceStatusActive
	d.LastSeenAt = time.Now()
	d.CreatedAt = time.Now()

	// Compute trust score
	d.TrustScore = s.computeTrustScore(d)

	if err := s.deviceRepo.Store(d); err != nil {
		return nil, fmt.Errorf("store device: %w", err)
	}
	return d, nil
}

// EnableBiometric stores the device's public key after successful enrollment.
func (s *DeviceService) EnableBiometric(deviceID, userID string, params EnableBiometricParams) error {
	device, err := s.deviceRepo.GetByID(deviceID)
	if err != nil || device == nil {
		return ErrDeviceNotFound
	}
	if device.UserID != userID {
		return ErrDeviceOwnership
	}

	now := time.Now()
	device.BiometricEnabled = true
	device.PublicKey = params.PublicKey
	device.KeyID = params.KeyID
	device.BiometricType = params.BiometricType
	device.AttestationData = params.AttestationData
	device.IsRooted = params.IsRooted
	device.IsJailbroken = params.IsJailbroken
	device.EnrolledAt = &now
	device.TrustScore = s.computeTrustScore(device)

	return s.deviceRepo.Update(device)
}

// GetDevice retrieves a device, checking it's active.
func (s *DeviceService) GetDevice(deviceID string) (*domain.Device, error) {
	return s.deviceRepo.GetByID(deviceID)
}

// ListUserDevices returns all devices for a user.
func (s *DeviceService) ListUserDevices(userID string) ([]*domain.Device, error) {
	return s.deviceRepo.ListByUser(userID)
}

// RevokeDevice revokes a specific device — all sessions on it become invalid.
func (s *DeviceService) RevokeDevice(deviceID, userID, revokedBy string) error {
	device, err := s.deviceRepo.GetByID(deviceID)
	if err != nil || device == nil {
		return ErrDeviceNotFound
	}
	if device.UserID != userID {
		return ErrDeviceOwnership
	}

	now := time.Now()
	device.Status = domain.DeviceStatusRevoked
	device.RevokedAt = &now
	device.RevokedBy = revokedBy
	device.BiometricEnabled = false
	device.PublicKey = "" // Clear key — device can no longer authenticate

	if err := s.deviceRepo.Update(device); err != nil {
		return fmt.Errorf("update device: %w", err)
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:   userID,
		DeviceID: deviceID,
		Action:   domain.AuditActionDeviceRevoked,
		Result:   domain.AuditResultSuccess,
		Details:  map[string]any{"revoked_by": revokedBy},
	})

	return nil
}

// ValidateDevice checks device is active and not rooted.
func (s *DeviceService) ValidateDevice(deviceID, userID string) (*domain.Device, error) {
	device, err := s.deviceRepo.GetByID(deviceID)
	if err != nil || device == nil {
		return nil, ErrDeviceNotFound
	}
	if device.UserID != userID {
		return nil, ErrDeviceOwnership
	}

	switch device.Status {
	case domain.DeviceStatusRevoked:
		return nil, ErrDeviceRevoked
	case domain.DeviceStatusBlocked:
		return nil, ErrDeviceBlocked
	}

	return device, nil
}

// UpdateLastSeen updates the device's last seen timestamp.
func (s *DeviceService) UpdateLastSeen(deviceID string) error {
	device, err := s.deviceRepo.GetByID(deviceID)
	if err != nil {
		return err
	}
	device.LastSeenAt = time.Now()
	return s.deviceRepo.Update(device)
}

// computeTrustScore calculates a 0-100 trust score for the device.
// Used for risk-based auth decisions (could block high-risk step-up).
func (s *DeviceService) computeTrustScore(d *domain.Device) int {
	score := 100

	if d.IsRooted || d.IsJailbroken {
		score -= 60
	}
	if d.AttestationData == "" {
		score -= 20
	}
	if d.AppVersion == "" {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	return score
}
