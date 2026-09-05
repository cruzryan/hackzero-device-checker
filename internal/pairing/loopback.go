package pairing

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Loopback receives exactly one OAuth authorization-code callback. It listens
// only on 127.0.0.1 and validates state before exposing the code to its caller.
// The caller must exchange the code over HTTPS; this package never persists it.
type Loopback struct {
	listener net.Listener
	server   *http.Server
	result   chan Result
	once     sync.Once
}

// Result is the narrow result of a browser pairing callback.
type Result struct {
	Code string
	Err  error
}

// StartLoopback binds an ephemeral local port and begins receiving /callback.
func StartLoopback(session Session) (*Loopback, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	callback := &Loopback{listener: listener, result: make(chan Result, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !session.ValidCallbackState(request.URL.Query().Get("state")) {
			callback.finish(Result{Err: errors.New("pairing callback state did not match")})
			http.Error(w, "pairing could not be verified", http.StatusBadRequest)
			return
		}
		if providerError := request.URL.Query().Get("error"); providerError != "" {
			callback.finish(Result{Err: errors.New("pairing was declined: " + providerError)})
			http.Error(w, "pairing was declined; you may close this tab", http.StatusBadRequest)
			return
		}
		code := request.URL.Query().Get("code")
		if code == "" {
			callback.finish(Result{Err: errors.New("pairing callback contained no authorization code")})
			http.Error(w, "pairing could not be completed", http.StatusBadRequest)
			return
		}
		callback.finish(Result{Code: code})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Device connected</title><style>body{margin:0;background:#09090b;color:#f8f7f4;font:16px/1.5 Arial,sans-serif}.wrap{max-width:560px;margin:12vh auto;padding:34px;border:1px solid #3b3d43;border-radius:18px;background:#15161a}.eyebrow{color:#9fc8ff;font:700 11px Consolas,monospace;letter-spacing:.14em}h1{margin:14px 0 10px;font:400 42px/1 Georgia,serif}p{color:#d0d1d7}</style><main class="wrap"><div class="eyebrow">HACKZERO DEVICE CHECKER</div><h1>Device connected.</h1><p>Return to Device Checker. It will finish the secure connection now.</p></main></html>`))
	})
	callback.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = callback.server.Serve(listener) }()
	redirect := (&url.URL{Scheme: "http", Host: listener.Addr().String(), Path: "/callback"}).String()
	return callback, redirect, nil
}

// Wait returns the callback result or context cancellation. It always closes
// the loopback listener before returning.
func (l *Loopback) Wait(context context.Context) Result {
	defer l.Close()
	select {
	case result := <-l.result:
		return result
	case <-context.Done():
		return Result{Err: context.Err()}
	}
}

// Close stops the local listener. It is safe to call more than once.
func (l *Loopback) Close() {
	l.once.Do(func() { _ = l.server.Close() })
}

func (l *Loopback) finish(result Result) {
	select {
	case l.result <- result:
	default:
	}
}
