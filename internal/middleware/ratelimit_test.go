package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/17xande-dev/budget/internal/middleware"
	"github.com/17xande-dev/ratelimit"
	"github.com/17xande-dev/ratelimit/clientip"
	"golang.org/x/time/rate"
)

func newLimiter(t *testing.T, burst int) *ratelimit.Limiter {
	t.Helper()
	l, err := ratelimit.New(ratelimit.Config{Rate: rate.Every(time.Hour), Burst: burst})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func post(h http.Handler, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// Exhausting the limiter by IP answers with this app's 429: status, plain-text
// body, and no Retry-After (the login form tells the person to wait a minute).
func TestByIPExhaustedGivesTheApps429(t *testing.T) {
	h := middleware.ByIP(newLimiter(t, 2), clientip.Source{})(ok)
	for i := range 2 {
		if rec := post(h, "203.0.113.9:1234", nil); rec.Code != 200 {
			t.Fatalf("request %d = %d, want 200", i, rec.Code)
		}
	}
	rec := post(h, "203.0.113.9:1234", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third = %d, want 429", rec.Code)
	}
	if got, want := rec.Body.String(), "Too many attempts. Please wait a minute and try again.\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content type = %q", ct)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "" {
		t.Errorf("Retry-After = %q, want none", ra)
	}
	if rec := post(h, "198.51.100.1:1234", nil); rec.Code != 200 {
		t.Errorf("a different IP was limited: %d", rec.Code)
	}
}

// An IPv6 client can use any address in its /64; rotating them must not earn a
// fresh bucket.
func TestByIPKeysIPv6ByPrefix(t *testing.T) {
	h := middleware.ByIP(newLimiter(t, 2), clientip.Source{})(ok)
	var codes []int
	for _, addr := range []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:2", "[2001:db8:1:2:aaaa::3]:3"} {
		codes = append(codes, post(h, addr, nil).Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want 200 200 429", codes)
	}
}

// The wiring from CLIENT_IP_SOURCE to a key: an untrusted caller must not choose
// its own bucket by sending a header the deployment does not vouch for.
func TestByIPSourceSpoofing(t *testing.T) {
	cf, err := clientip.ParseSource("cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	fwd, err := clientip.ParseSource("forwarded")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		src clientip.Source
		// header values for the two requests; the second is a different
		// "client" by header alone. Same peer both times.
		hdr1, hdr2 map[string]string
		wantSecond int
	}{
		"remote ignores CF-Connecting-IP": {clientip.Source{},
			map[string]string{"CF-Connecting-IP": "1.1.1.1"}, map[string]string{"CF-Connecting-IP": "2.2.2.2"}, 429},
		"remote ignores X-Forwarded-For": {clientip.Source{},
			map[string]string{"X-Forwarded-For": "1.1.1.1"}, map[string]string{"X-Forwarded-For": "2.2.2.2"}, 429},
		"cloudflare trusts CF-Connecting-IP": {cf,
			map[string]string{"CF-Connecting-IP": "1.1.1.1"}, map[string]string{"CF-Connecting-IP": "2.2.2.2"}, 200},
		"cloudflare same client shares a bucket": {cf,
			map[string]string{"CF-Connecting-IP": "1.1.1.1"}, map[string]string{"CF-Connecting-IP": "1.1.1.1"}, 429},
		"cloudflare ignores X-Forwarded-For": {cf,
			map[string]string{"X-Forwarded-For": "1.1.1.1"}, map[string]string{"X-Forwarded-For": "2.2.2.2"}, 429},
		"forwarded trusts leftmost X-Forwarded-For": {fwd,
			map[string]string{"X-Forwarded-For": "1.1.1.1"}, map[string]string{"X-Forwarded-For": "2.2.2.2"}, 200},
		"forwarded ignores CF-Connecting-IP": {fwd,
			map[string]string{"CF-Connecting-IP": "1.1.1.1"}, map[string]string{"CF-Connecting-IP": "2.2.2.2"}, 429},
	} {
		t.Run(name, func(t *testing.T) {
			h := middleware.ByIP(newLimiter(t, 1), tc.src)(ok)
			if rec := post(h, "10.0.0.1:1", tc.hdr1); rec.Code != 200 {
				t.Fatalf("first = %d", rec.Code)
			}
			if rec := post(h, "10.0.0.1:2", tc.hdr2); rec.Code != tc.wantSecond {
				t.Errorf("second = %d, want %d", rec.Code, tc.wantSecond)
			}
		})
	}
}
