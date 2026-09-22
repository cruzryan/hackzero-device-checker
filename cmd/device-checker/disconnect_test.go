package main

import (
	"errors"
	"net/http"
	"testing"
)

func TestServerForgotDevice(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unknown_device 401", &httpError{status: http.StatusUnauthorized, body: `{"error":"unknown_device"}`}, true},
		{"not found 404", &httpError{status: http.StatusNotFound}, true},
		{"gone 410", &httpError{status: http.StatusGone}, true},
		{"server error 500 keeps state", &httpError{status: http.StatusInternalServerError}, false},
		{"bad request 400 keeps state", &httpError{status: http.StatusBadRequest}, false},
		{"transport error keeps state", errors.New("dial tcp: connection refused"), false},
		{"nil error", nil, false},
	}
	for _, c := range cases {
		if got := serverForgotDevice(c.err); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
