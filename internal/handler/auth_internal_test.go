package handler

import "testing"

// safeNext is a thin wrapper over websec.SafeRedirect, which owns the algorithm
// and its own table. This pins the wiring: the options this app passes (no
// Prefix, no Deny, homePath as the fallback), one hostile row, and the value
// the auth middleware actually generates.
func TestSafeNext(t *testing.T) {
	for _, tc := range []struct{ name, next, want string }{
		// A browser drops a literal tab from a URL, so this reads "//evil.example":
		// an open redirect after sign-in if accepted. (The %09 spelling is a
		// different case: a browser keeps it on this host, and websec refuses it
		// anyway.)
		{"tab hides a second slash", "/\t/evil.example", homePath},
		{"other host", "https://evil.example/", homePath},
		{"empty falls back", "", homePath},
		// The middleware sends an unauthenticated visitor to /login?next=<RequestURI>,
		// so a path with a query must come back byte for byte.
		{"middleware RequestURI with a query", "/sheet/arches?month=2026-10&q=a%20b", "/sheet/arches?month=2026-10&q=a%20b"},
		{"root", "/", "/"},
		// This app denies nothing: /login is a legal target here (the signed-in
		// bounce in LoginForm handles it).
		{"no deny list", "/login", "/login"},
	} {
		if got := safeNext(tc.next); got != tc.want {
			t.Errorf("%s: safeNext(%q) = %q, want %q", tc.name, tc.next, got, tc.want)
		}
	}
}
