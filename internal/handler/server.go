package handler

import (
	"net/http"

	"github.com/17xande-dev/budget/internal/middleware"
	"github.com/17xande-dev/websec/csrf"
)

// maxFormBytes bounds every request body except an import upload. The forms are
// a few fields; nothing legitimate comes close.
const maxFormBytes = 1 << 20

// importPattern is the one route that accepts a multipart upload.
const importPattern = "POST /import"

// newCSRF builds the request-forgery policy before any handler exists, so the
// sign-in, sign-out and password-change handlers can renew the token. origin is
// the public origin browsers use; pattern reports the route the app's mux picks
// (caps follow the pattern, never a prefix of the path).
func newCSRF(origin string, secure bool, pattern func(*http.Request) string) (*csrf.Protect, error) {
	return csrf.New(csrf.Config{
		Origin:   origin,
		Insecure: !secure,
		MaxBody:  maxFormBytes,
		Limit: func(r *http.Request) csrf.BodyLimit {
			if pattern(r) == importPattern {
				// MaxMemory is the whole cap, so an upload stays in memory and is
				// never written to a temporary file; non-multipart bodies on this
				// route keep the 1 MiB form cap.
				return csrf.BodyLimit{MultipartMaxBytes: MaxUploadBytes, MaxMemory: MaxUploadBytes}
			}
			return csrf.BodyLimit{}
		},
		OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) {
			if status == http.StatusRequestEntityTooLarge {
				http.Error(w, "That upload is too large.", status)
				return
			}
			http.Error(w, http.StatusText(status), status)
		},
	})
}

// Server composes the whole HTTP stack: routes, CSRF, security headers. It lives
// here rather than in main so the tests exercise exactly the stack production
// runs -- the order of these layers is itself something worth testing.
//
// protect is RequireUser; limit is the per-IP limiter for secret-verifying routes.
// mcpHandler, when not nil, is the MCP endpoint (internal/mcpserver).
func (h *Handler) Server(protect, limit func(http.Handler) http.Handler, mcpHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	h.Register(mux, protect, limit)
	h.mux.Store(mux)

	// The form-protection layer reads the whole form -- a multipart upload
	// included -- before any handler runs, and caps it first (see newCSRF), so a
	// limit inside a handler would come too late.
	protected := h.csrf.Handler(mux)

	// The MCP endpoint sits beside the CSRF layer, not inside it: it is
	// authenticated by a bearer token alone, never a cookie, so there is no
	// ambient credential for a forged request to ride on -- and the CSRF layer
	// would refuse every MCP client, which sends no CSRF token. A test pins these
	// two lines, so nothing else gets mounted outside it by accident.
	root := http.NewServeMux()
	if mcpHandler != nil {
		mcpCapped := capBody(mcpHandler, maxFormBytes)
		root.Handle("/mcp", mcpCapped)
	}
	root.Handle("/", protected)

	// Security headers outermost, so they are on every response: a CSRF refusal
	// and a 404 included.
	return middleware.SecurityHeaders(root)
}

// capBody caps a request body the way it is read, and refuses one that declares
// more up front. It guards /mcp, which sits outside the CSRF layer's caps.
func capBody(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			http.Error(w, "That request is too large.", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}
