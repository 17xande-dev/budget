package middleware

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/17xande-dev/budget/internal/auth"
	"github.com/17xande-dev/websec/cookie"
)

// SessionCookieName is the session cookie's bare name; on https the cookie
// policy (websec/cookie) adds the __Host- prefix. It is always HttpOnly and
// SameSite=Lax.
const SessionCookieName = "budget_session"

// userKey is the context key the signed-in user is stored under. Unexported, so
// nothing outside this package can forge one.
type userKey struct{}

// User returns the signed-in user from a request that passed through RequireUser.
// False should be impossible on a protected route, so a handler that sees it has
// been mounted wrong.
func User(r *http.Request) (auth.User, bool) {
	u, ok := r.Context().Value(userKey{}).(auth.User)
	return u, ok
}

// WithUser returns r carrying u as the signed-in user. RequireUser is the only
// production caller; it is exported as the test seam for rendering a page as
// someone without a real sign-in.
func WithUser(r *http.Request, u auth.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey{}, u))
}

// RequireUser rejects requests without a valid session.
//
// A browser navigating to a protected page is redirected to the login form with
// where it was going in ?next=. An htmx request is not redirected -- swapping a
// login page into a fragment of the current page makes a broken hybrid -- so it
// gets a 401 and a header telling htmx to reload the page properly.
func RequireUser(store *auth.Store, session *cookie.Cookie) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token, found := session.Value(r); found {
				u, ok, err := store.VerifySession(token, time.Now())
				if err != nil {
					// A database failure is not an authentication failure;
					// redirecting would send someone round a login loop with
					// no clue why.
					log.Printf("auth: verify session: %v", err)
					http.Error(w, "Internal error", http.StatusInternalServerError)
					return
				}
				if ok {
					next.ServeHTTP(w, WithUser(r, u))
					return
				}
			}
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Refresh", "true")
				http.Error(w, "Unauthorised", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		})
	}
}
