// Package identity owns the device signing key. It has no authority to obtain
// a user session or make network calls.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Device is the minimal durable local identity. The private key is never
// marshalled into reports; callers should store this file in an OS-backed
// credential store when one is wired in by the platform service.
type Device struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	privateKey string
}

type persisted struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// New creates an independent Ed25519 identity. IDs are opaque random values,
// not host names, serial numbers, or user identifiers.
func New() (Device, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Device{}, fmt.Errorf("generate device key: %w", err)
	}
	idBytes := make([]byte, 18)
	if _, err := rand.Read(idBytes); err != nil {
		return Device{}, fmt.Errorf("generate device id: %w", err)
	}
	return Device{
		ID:         base64.RawURLEncoding.EncodeToString(idBytes),
		PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
		privateKey: base64.RawURLEncoding.EncodeToString(privateKey),
	}, nil
}

// Sign produces a detached Ed25519 signature over the exact bytes supplied.
func (d Device) Sign(message []byte) (string, error) {
	key, err := base64.RawURLEncoding.DecodeString(d.privateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid device private key")
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), message)), nil
}

// Verify verifies a signature using the device's public key.
func (d Device) Verify(message []byte, signature string) bool {
	publicKey, publicErr := base64.RawURLEncoding.DecodeString(d.PublicKey)
	sig, signatureErr := base64.RawURLEncoding.DecodeString(signature)
	return publicErr == nil && signatureErr == nil && len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(publicKey), message, sig)
}

// Save writes restrictive local state atomically. Callers supply the state
// path so service installers can use their platform-appropriate data folder.
func (d Device) Save(path string) error {
	if _, err := d.Sign([]byte("validation")); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	data, err := json.Marshal(persisted{ID: d.ID, PublicKey: d.PublicKey, PrivateKey: d.privateKey})
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return fmt.Errorf("create identity file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect identity file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close identity: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace identity: %w", err)
	}
	return os.Chmod(path, 0600)
}

// Load validates a stored identity before returning it.
func Load(path string) (Device, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Device{}, err
	}
	var stored persisted
	if err := json.Unmarshal(data, &stored); err != nil {
		return Device{}, fmt.Errorf("decode identity: %w", err)
	}
	d := Device{ID: stored.ID, PublicKey: stored.PublicKey, privateKey: stored.PrivateKey}
	if d.ID == "" || !d.Verify([]byte("validation"), mustSign(d, []byte("validation"))) {
		return Device{}, errors.New("invalid stored device identity")
	}
	return d, nil
}

func mustSign(d Device, message []byte) string {
	signature, err := d.Sign(message)
	if err != nil {
		return ""
	}
	return signature
}
