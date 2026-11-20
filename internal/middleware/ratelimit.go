package middleware

import (
	"net/http"

	"github.com/17xande-dev/ratelimit"
	"github.com/17xande-dev/ratelimit/clientip"
)

// ByIP wraps a handler so each client IP spends a token from l per request,
// reading the address as source says to. A refusal is the plain-text 429 the
// login and secret-verifying routes have always answered with.
func ByIP(l *ratelimit.Limiter, source clientip.Source) func(http.Handler) http.Handler {
	return l.Middleware(source, ratelimit.HTTPOptions{
		Exceeded: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Too many attempts. Please wait a minute and try again.", http.StatusTooManyRequests)
		}),
	})
}
