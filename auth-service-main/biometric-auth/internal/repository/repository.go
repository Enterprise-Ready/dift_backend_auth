package repository

import (
	"errors"
	"sync"
	"time"

	"biometric-auth/internal/domain"
)

// ─── Interfaces ───────────────────────────────────────────────────────────────

type UserRepository interface {
	FindByID(id string) (*domain.User, error)
	FindByIdentifier(identifier string) (*domain.User, error)
	Store(user *domain.User) error
	Update(user *domain.User) error
}

type DeviceRepository interface {
	GetByID(id string) (*domain.Device, error)
	ListByUser(userID string) ([]*domain.Device, error)
	Store(device *domain.Device) error
	Update(device *domain.Device) error
}

type SessionRepository interface {
	GetByID(id string) (*domain.Session, error)
	Store(session *domain.Session) error
	Update(session *domain.Session) error
	RevokeFamily(family string, status domain.SessionStatus) error
	RevokeAllByUser(userID string) error
}

type AuditRepository interface {
	Store(log *domain.AuditLog) error
	GetByUser(userID string, limit, offset int) ([]*domain.AuditLog, error)
	GetAll(limit, offset int) ([]*domain.AuditLog, error)
}

type ChallengeRepository interface {
	Store(challenge *domain.Challenge) error
	Get(id string) (*domain.Challenge, error)
	Update(challenge *domain.Challenge) error
	DeleteExpired() error
}

// ─── In-Memory Implementations ───────────────────────────────────────────────

// UserRepository

type inMemoryUserRepo struct {
	mu    sync.RWMutex
	users map[string]*domain.User
}

func NewUserRepository() UserRepository {
	repo := &inMemoryUserRepo{users: make(map[string]*domain.User)}
	// Seed a test user
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
	repo.users["user_001"] = &domain.User{
		ID:           "user_001",
		Phone:        "+66812345678",
		Email:        "test@example.com",
		PasswordHash: hash,
		Status:       domain.UserStatusActive,
		CreatedAt:    time.Now(),
	}
	return repo
}

func (r *inMemoryUserRepo) FindByID(id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (r *inMemoryUserRepo) FindByIdentifier(identifier string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.Phone == identifier || u.Email == identifier {
			return u, nil
		}
	}
	return nil, errors.New("user not found")
}

func (r *inMemoryUserRepo) Store(user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
	return nil
}

func (r *inMemoryUserRepo) Update(user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user.UpdatedAt = time.Now()
	r.users[user.ID] = user
	return nil
}

// DeviceRepository

type inMemoryDeviceRepo struct {
	mu      sync.RWMutex
	devices map[string]*domain.Device
}

func NewDeviceRepository() DeviceRepository {
	return &inMemoryDeviceRepo{devices: make(map[string]*domain.Device)}
}

func (r *inMemoryDeviceRepo) GetByID(id string) (*domain.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.devices[id]
	if !ok {
		return nil, nil
	}
	return d, nil
}

func (r *inMemoryDeviceRepo) ListByUser(userID string) ([]*domain.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*domain.Device
	for _, d := range r.devices {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (r *inMemoryDeviceRepo) Store(device *domain.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[device.ID] = device
	return nil
}

func (r *inMemoryDeviceRepo) Update(device *domain.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[device.ID] = device
	return nil
}

// SessionRepository

type inMemorySessionRepo struct {
	mu       sync.RWMutex
	sessions map[string]*domain.Session
}

func NewSessionRepository() SessionRepository {
	return &inMemorySessionRepo{sessions: make(map[string]*domain.Session)}
}

func (r *inMemorySessionRepo) GetByID(id string) (*domain.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (r *inMemorySessionRepo) Store(session *domain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.ID] = session
	return nil
}

func (r *inMemorySessionRepo) Update(session *domain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[session.ID] = session
	return nil
}

func (r *inMemorySessionRepo) RevokeFamily(family string, status domain.SessionStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.TokenFamily == family {
			s.Status = status
		}
	}
	return nil
}

func (r *inMemorySessionRepo) RevokeAllByUser(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		if s.UserID == userID {
			s.Status = domain.SessionStatusRevoked
		}
	}
	return nil
}

// AuditRepository

type inMemoryAuditRepo struct {
	mu   sync.RWMutex
	logs []*domain.AuditLog
}

func NewAuditRepository() AuditRepository {
	return &inMemoryAuditRepo{}
}

func (r *inMemoryAuditRepo) Store(log *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, log)
	return nil
}

func (r *inMemoryAuditRepo) GetByUser(userID string, limit, offset int) ([]*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*domain.AuditLog
	for _, l := range r.logs {
		if l.UserID == userID {
			result = append(result, l)
		}
	}
	return paginate(result, limit, offset), nil
}

func (r *inMemoryAuditRepo) GetAll(limit, offset int) ([]*domain.AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return paginate(r.logs, limit, offset), nil
}

func paginate(logs []*domain.AuditLog, limit, offset int) []*domain.AuditLog {
	if offset >= len(logs) {
		return nil
	}
	end := offset + limit
	if end > len(logs) {
		end = len(logs)
	}
	return logs[offset:end]
}

// ChallengeRepository

type inMemoryChallengeRepo struct {
	mu         sync.RWMutex
	challenges map[string]*domain.Challenge
}

func NewChallengeRepository() ChallengeRepository {
	return &inMemoryChallengeRepo{challenges: make(map[string]*domain.Challenge)}
}

func (r *inMemoryChallengeRepo) Store(c *domain.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[c.ID] = c
	return nil
}

func (r *inMemoryChallengeRepo) Get(id string) (*domain.Challenge, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.challenges[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (r *inMemoryChallengeRepo) Update(c *domain.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[c.ID] = c
	return nil
}

func (r *inMemoryChallengeRepo) DeleteExpired() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for id, c := range r.challenges {
		if now.After(c.ExpiresAt) {
			delete(r.challenges, id)
		}
	}
	return nil
}
