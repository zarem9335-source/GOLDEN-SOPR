package auth

import "testing"

func TestCheck(t *testing.T) {
	if !Check("admin", "secret", "admin", "secret") {
		t.Fatal("valid credentials rejected")
	}
	if Check("admin", "wrong", "admin", "secret") {
		t.Fatal("wrong password accepted")
	}
	if Check("admin", "secret", "", "") {
		t.Fatal("empty stored credentials accepted")
	}
}

func TestSessionStore(t *testing.T) {
	s := NewSessionStore(0)
	tok := s.Issue()
	if tok == "" || !s.Valid(tok) {
		t.Fatal("issued token not valid")
	}
	s.Revoke(tok)
	if s.Valid(tok) {
		t.Fatal("revoked token still valid")
	}
	if s.Valid("nope") {
		t.Fatal("bogus token valid")
	}
}
