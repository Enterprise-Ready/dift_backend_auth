package integration

import (
	"context"
	"errors"
	"strings"
	"sync"

	repoport "dift_backend_go/auth-service/internal/interface/repository"
)

type LocalIdentityStore struct {
	mu       sync.RWMutex
	byEmail  map[string]*repoport.IdentityUser
	userRole map[string][]repoport.IdentityRole
}

func NewLocalIdentityStore() *LocalIdentityStore {
	return &LocalIdentityStore{
		byEmail:  make(map[string]*repoport.IdentityUser),
		userRole: make(map[string][]repoport.IdentityRole),
	}
}

func (s *LocalIdentityStore) GetUserByEmail(ctx context.Context, email string) (*repoport.IdentityUser, error) {
	_ = ctx
	key := strings.ToLower(strings.TrimSpace(email))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byEmail[key]; ok {
		out := *u
		return &out, nil
	}
	return nil, nil
}

func (s *LocalIdentityStore) CreateEmailUser(ctx context.Context, name, email, password string) (*repoport.IdentityUser, error) {
	_ = ctx
	key := strings.ToLower(strings.TrimSpace(email))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[key]; ok {
		return nil, errors.New("email already exists")
	}
	u := &repoport.IdentityUser{
		ID:       "usr_" + strings.ReplaceAll(key, "@", "_"),
		Name:     strings.TrimSpace(name),
		Email:    key,
		Password: password,
	}
	s.byEmail[key] = u
	s.userRole[u.ID] = []repoport.IdentityRole{{Name: "user"}}
	out := *u
	return &out, nil
}

func (s *LocalIdentityStore) GetUserRoles(ctx context.Context, userID string) ([]repoport.IdentityRole, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if roles, ok := s.userRole[userID]; ok {
		cp := make([]repoport.IdentityRole, len(roles))
		copy(cp, roles)
		return cp, nil
	}
	return []repoport.IdentityRole{{Name: "user"}}, nil
}

func (s *LocalIdentityStore) Health(ctx context.Context) error {
	_ = ctx
	return nil
}
