// Package pairing provides the local, security-sensitive pieces of browser
// pairing. It deliberately does not implement a service endpoint or retain an
// OAuth bearer token.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
)

// Session contains one-use values for authorization-code + PKCE pairing.
// Verifier and State must never be written to logs or uploaded.
type Session struct{ Verifier, State string }

func NewSession() (Session, error) {
	verifier, err := randomURLValue(48)
	if err != nil {
		return Session{}, err
	}
	state, err := randomURLValue(24)
	if err != nil {
		return Session{}, err
	}
	return Session{Verifier: verifier, State: state}, nil
}

func (s Session) Challenge() string {
	digest := sha256.Sum256([]byte(s.Verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// AuthorizationURL adds only standards-defined pairing parameters. The caller
// supplies a pre-registered HTTPS authorization endpoint and loopback callback.
func (s Session) AuthorizationURL(endpoint, clientID, redirectURI string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("pairing endpoint must be HTTPS")
	}
	if clientID == "" || redirectURI == "" || s.Verifier == "" || s.State == "" {
		return "", errors.New("incomplete pairing session")
	}
	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("code_challenge", s.Challenge())
	query.Set("code_challenge_method", "S256")
	query.Set("state", s.State)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (s Session) ValidCallbackState(state string) bool { return s.State != "" && state == s.State }

func randomURLValue(bytes int) (string, error) {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
