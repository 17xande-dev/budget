package handler_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var inputTagRe = regexp.MustCompile(`<input[^>]*>`)

// loginInput returns the opening tag of the sign-in form's input with the
// given id, so a test can look at its attributes rather than at the page.
func loginInput(t *testing.T, body, id string) string {
	t.Helper()
	for _, tag := range inputTagRe.FindAllString(body, -1) {
		if strings.Contains(tag, ` id="`+id+`"`) {
			return tag
		}
	}
	t.Fatalf("no input with id %q in:\n%s", id, body)
	return ""
}

func hasAutofocus(tag string) bool { return strings.Contains(tag, " autofocus") }

// wantFocus checks the rule for a rendered sign-in page: the email field has
// focus while it is empty, the password field once an address is carried.
func wantFocus(t *testing.T, body string, passwordFocused bool) {
	t.Helper()
	if got := hasAutofocus(loginInput(t, body, "email")); got == passwordFocused {
		t.Errorf("email autofocus = %v with password focus wanted = %v", got, passwordFocused)
	}
	if got := hasAutofocus(loginInput(t, body, "password")); got != passwordFocused {
		t.Errorf("password autofocus = %v, want %v", got, passwordFocused)
	}
	if n := strings.Count(body, "autofocus"); n != 1 {
		t.Errorf("page has %d autofocus attributes, want exactly 1", n)
	}
}

func TestLoginFocusFreshPageFocusesEmail(t *testing.T) {
	e := newEnv(t)
	e.claim()
	r := e.browser().get("/login")
	if r.code != http.StatusOK {
		t.Fatalf("GET /login: %d", r.code)
	}
	wantFocus(t, r.body, false)
}

func TestLoginFocusFailureFocusesPasswordKeepsEmail(t *testing.T) {
	e := newEnv(t)
	e.claim()
	const typed = "owner@example.com"
	const wrongPW = "wrong-pw-<xyz>-987"
	wrong := e.browser().login(typed, wrongPW)
	if wrong.code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d, want 401", wrong.code)
	}
	wantFocus(t, wrong.body, true)
	if v := loginInput(t, wrong.body, "email"); !strings.Contains(v, `value="owner@example.com"`) {
		t.Errorf("email field lost the submitted address: %s", v)
	}
	for _, leak := range []string{wrongPW, "wrong-pw-&lt;xyz&gt;-987", "wrong-pw-&#60;xyz&#62;-987"} {
		if strings.Contains(wrong.body, leak) {
			t.Errorf("password echoed into the page as %q", leak)
		}
	}
	if v := loginInput(t, wrong.body, "password"); strings.Contains(v, "value=") {
		t.Errorf("password field carries a value: %s", v)
	}

	unknown := e.browser().login("nobody@example.com", wrongPW)
	if unknown.code != wrong.code {
		t.Fatalf("unknown user: %d, want %d", unknown.code, wrong.code)
	}
	wantFocus(t, unknown.body, true)
	if loginInput(t, unknown.body, "password") != loginInput(t, wrong.body, "password") {
		t.Error("password markup differs between unknown user and wrong password")
	}
	if v := loginInput(t, unknown.body, "email"); !strings.Contains(v, `value="nobody@example.com"`) {
		t.Errorf("unknown user's address not preserved: %s", v)
	}
}

func TestLoginFocusEscapesSubmittedEmail(t *testing.T) {
	e := newEnv(t)
	e.claim()
	r := e.browser().login(`a"><script>x</script>@example.com`, "pw")
	if strings.Contains(r.body, "<script>x") {
		t.Error("submitted address rendered unescaped")
	}
	wantFocus(t, r.body, true)
}

func TestLoginFocusRateLimitedKeepsRule(t *testing.T) {
	e := newEnv(t)
	e.claim()
	b := e.browser()
	var r resp
	for i := 0; i < 8 && r.code != http.StatusTooManyRequests; i++ {
		r = b.post("/login", "/login", url.Values{"email": {"owner@example.com"}, "password": {"nope-" + strings.Repeat("x", i)}})
	}
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("never rate limited, last %d", r.code)
	}
	wantFocus(t, r.body, true)
}
