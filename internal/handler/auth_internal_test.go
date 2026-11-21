package handler

import (
	"strings"
	"testing"
)

// A browser reads "/%09/evil.example" and "/\t/evil" as "//evil.example" (it
// drops tabs and newlines), and "/\\evil" as "//evil": every one of these
// would be an open redirect after sign-in. A refusal lands on homePath.
func TestSafeNext(t *testing.T) {
	for next, want := range map[string]string{
		"/progress":                     "/progress",
		"/sheet/arches?x=1#y":           "/sheet/arches?x=1#y",
		"/":                             "/",
		"":                              homePath,
		"/%09/evil.example":             homePath,
		"/\t/evil":                      homePath,
		"/\n/evil":                      homePath,
		"/\\evil":                       homePath,
		"/\\\\evil":                     homePath,
		"/%5Cevil":                      homePath,
		"https://evil":                  homePath,
		"//evil":                        homePath,
		"///evil":                       homePath,
		"evil":                          homePath,
		"/%2F/evil":                     homePath, // decodes to "//evil"; refused even though a browser would keep it one segment
		"/a\x00b":                       homePath,
		"/a\x7fb":                       homePath,
		"javascript:alert(1)":           homePath,
		"/%0a/evil.example":             homePath,
		"/..%2f..%2fetc":                "/..%2f..%2fetc",
		"/ok?next=//evil":               "/ok?next=//evil",
		"/ /evil":                       "/ /evil",
		"/%00":                          homePath,
		"/path with space":              "/path with space",
		"/%":                            homePath,
		"/%zz":                          homePath,
		"/a/\x1f":                       homePath,
		"//":                            homePath,
		"/\r/evil":                      homePath,
		"http://evil.example/":          homePath,
		"/\v/evil.example":              homePath,
		"/\f/evil.example":              homePath,
		"/a\\b":                         homePath,
		"/x?\\evil":                     homePath,
		"/x#\\evil":                     homePath,
		"/" + strings.Repeat("a", 2047): "/" + strings.Repeat("a", 2047),
		"/" + strings.Repeat("a", 2048): homePath,
	} {
		if got := safeNext(next); got != want {
			t.Errorf("safeNext(%.40q) = %.40q, want %.40q", next, got, want)
		}
	}
}
