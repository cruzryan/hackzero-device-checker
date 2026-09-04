package pairing

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestLoopbackAcceptsOneMatchingCallback(t *testing.T) {
	session, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	loopback, redirect, err := StartLoopback(session)
	if err != nil {
		t.Fatal(err)
	}
	url, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Query()
	query.Set("state", session.State)
	query.Set("code", "one-time-code")
	url.RawQuery = query.Encode()
	response, err := http.Get(url.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := loopback.Wait(ctx)
	if result.Err != nil || result.Code != "one-time-code" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestLoopbackRejectsMismatchedState(t *testing.T) {
	session, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	loopback, redirect, err := StartLoopback(session)
	if err != nil {
		t.Fatal(err)
	}
	url, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Query()
	query.Set("state", "not-the-session")
	query.Set("code", "one-time-code")
	url.RawQuery = query.Encode()
	response, err := http.Get(url.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result := loopback.Wait(ctx); result.Err == nil {
		t.Fatal("expected state validation error")
	}
}
