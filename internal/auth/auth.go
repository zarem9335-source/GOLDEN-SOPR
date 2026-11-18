// Package auth: password checking and short-lived session tokens for the
// GOLDEN SOPR web panel. Stdlib only. Based on BackPack by Amin Mohammadi
// (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// Check compares user/password in constant time. Empty stored credentials
// never authenticate.
func Check(username, password, wantUser, wantPass string) bool {
	if wantUser == "" || wantPass == "" {
		return false
	}
	u := subtle.ConstantTimeCompare([]byte(username), []byte(wantUser)) == 1
	p := subtle.ConstantTimeCompare([]byte(password), []byte(wantPass)) == 1
	// Compare lengths too: ConstantTimeCompare returns 0 on length mismatch,
	// so the above already fails, but keep the intent explicit.
	return u && p && len(username) == len(wantUser) && len(password) == len(wantPass)
}

// GeneratePassword returns a random URL-safe password of n bytes (default 12).
func GeneratePassword(n int) string {
	if n <= 0 {
		n = 12
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to time-seeded bytes is worse than
		// failing, so return a fixed-length placeholder the caller must replace.
		return "sopr-change-me"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// SessionStore holds bearer tokens issued after a successful login.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{sessions: map[string]time.Time{}, ttl: ttl}
}

// Issue creates a new random 32-byte token valid for the store TTL.
func (s *SessionStore) Issue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return tok
}

// Valid reports whether tok is a live session token.
func (s *SessionStore) Valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[tok]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, tok)
		return false
	}
	return true
}

// Revoke removes a token.
func (s *SessionStore) Revoke(tok string) {
	s.mu.Lock()
	delete(s.sessions, tok)
	s.mu.Unlock()
}

// Cleanup removes expired tokens. Call periodically.
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for tok, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, tok)
		}
	}
}
