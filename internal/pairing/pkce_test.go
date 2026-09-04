package pairing

import (
	"net/url"
	"testing"
)

func TestPKCEAuthorizationURL(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	address, err := s.AuthorizationURL("https://example.test/authorize", "desktop", "http://127.0.0.1:41000/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(address)
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") != s.State {
		t.Fatal("missing PKCE parameters")
	}
	if !s.ValidCallbackState(s.State) || s.ValidCallbackState("wrong") {
		t.Fatal("state validation broken")
	}
}

func TestPKCERejectsInsecureEndpoint(t *testing.T) {
	s, _ := NewSession()
	if _, err := s.AuthorizationURL("http://example.test", "desktop", "callback"); err == nil {
		t.Fatal("accepted HTTP endpoint")
	}
}
