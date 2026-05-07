package authengine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID           string
	UserID       string
	RefreshToken string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
type Engine struct {
	mu       sync.RWMutex
	sessions map[string]Session
	revoked  map[string]time.Time
}

func New() *Engine { return &Engine{sessions: map[string]Session{}, revoked: map[string]time.Time{}} }
func (e *Engine) CreateSession(userID, refreshToken string, ttl time.Duration) (Session, error) {
	if strings.TrimSpace(userID) == "" {
		return Session{}, errors.New("user_id required")
	}
	id := randomID("sess")
	s := Session{ID: id, UserID: userID, RefreshToken: refreshToken, ExpiresAt: time.Now().Add(ttl), CreatedAt: time.Now()}
	e.mu.Lock()
	e.sessions[id] = s
	e.mu.Unlock()
	return s, nil
}
func (e *Engine) RevokeRefreshToken(token string) {
	e.mu.Lock()
	e.revoked[token] = time.Now()
	e.mu.Unlock()
}
func (e *Engine) IsRefreshTokenRevoked(token string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.revoked[token]
	return ok
}
func (e *Engine) Cleanup(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, s := range e.sessions {
		if now.After(s.ExpiresAt) {
			delete(e.sessions, id)
		}
	}
}
func randomID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
