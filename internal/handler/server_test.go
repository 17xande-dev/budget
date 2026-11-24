package handler

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The body limit has to act before the form is parsed, and must answer a
// declared-oversized body with 413 rather than letting it through to become a
// confusing CSRF failure. Run through the real policy over the real route
// patterns: only the import route earns the large allowance, and only for
// multipart.
func TestBodyLimits(t *testing.T) {
	mux := http.NewServeMux()
	var reached bool
	for _, p := range []string{importPattern, "POST /members"} {
		mux.HandleFunc(p, func(http.ResponseWriter, *http.Request) { reached = true })
	}
	p, err := newCSRF("https://budget.example", true, func(r *http.Request) string { _, pat := mux.Handler(r); return pat })
	if err != nil {
		t.Fatal(err)
	}
	h := p.Handler(mux)

	multipartBody := func() (io.Reader, string) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		w.WriteField("x", "y")
		w.Close()
		return &b, w.FormDataContentType()
	}
	cases := []struct {
		name, path, ctype string
		length            int64
		want              int // 413 or 403 (the token is checked after the cap, so under the cap it is 403)
	}{
		{"import at the cap", "/import", "multipart", MaxUploadBytes, 403},
		{"import over the cap", "/import", "multipart", MaxUploadBytes + 1, http.StatusRequestEntityTooLarge},
		{"form over 1 MiB", "/members", "form", maxFormBytes + 1, http.StatusRequestEntityTooLarge},
		{"form under 1 MiB", "/members", "form", 100, 403},
		// The import's large allowance is for multipart only.
		{"import with a form body over 1 MiB", "/import", "form", maxFormBytes + 1, http.StatusRequestEntityTooLarge},
		// Multipart is refused outside the import route.
		{"multipart on another route", "/members", "multipart", 100, http.StatusUnsupportedMediaType},
	}
	for _, c := range cases {
		reached = false
		var body io.Reader = strings.NewReader("")
		ctype := "application/x-www-form-urlencoded"
		if c.ctype == "multipart" {
			body, ctype = multipartBody()
		}
		req := httptest.NewRequest("POST", "https://budget.example"+c.path, body)
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("Origin", "https://budget.example")
		if c.length > 100 {
			req.ContentLength = c.length
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want || reached {
			t.Errorf("%s: %d (reached=%v), want %d", c.name, rec.Code, reached, c.want)
		}
		if c.want == http.StatusRequestEntityTooLarge && !strings.Contains(rec.Body.String(), "That upload is too large.") {
			t.Errorf("%s: body %q", c.name, rec.Body.String())
		}
	}
}
