package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sbomdelta/internal/auth"
)

// dataPaths is every GET route that exposes repository, scan, pull request,
// component, drift, vulnerability or SBOM data, plus /api/me.
func dataPaths(f fixture) []string {
	repo := jsonID(f.revoked.ID)
	scan := jsonID(f.scan.ID)
	return []string{
		"/api/me",
		"/api/repos",
		"/api/repos?access=all",
		"/api/repos/" + repo,
		"/api/repos/" + repo + "/scans",
		"/api/repos/" + repo + "/drift",
		"/api/repos/" + repo + "/pulls",
		"/api/pulls/1",
		"/api/scans/" + scan,
		"/api/scans/" + scan + "/components",
		"/api/scans/" + scan + "/drift",
		"/api/scans/" + scan + "/vulnerabilities",
		"/api/scans/" + scan + "/sbom",
	}
}

func serve(f fixture, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

// leaksData reports whether a response body names the fixture's repositories
// or scan -- the data every refused request must withhold.
func leaksData(body string) bool {
	return strings.Contains(body, "kept") || strings.Contains(body, "dropped") ||
		strings.Contains(body, "4444444444444444444444444444444444444444")
}

func TestEveryDataEndpointRequiresSignIn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	expired := newSession(t, f.db, 4002, "devmind2320-expired")
	// Allowed when it signed in, but the login is not on this server's list.
	outsider := newSession(t, f.db, 4003, "someone-else")
	if _, err := f.db.Pool().Exec(ctx,
		`UPDATE sessions SET expires_at = now() - interval '1 second'
		 WHERE user_id = (SELECT id FROM users WHERE login = 'devmind2320-expired')`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		cookie *http.Cookie
		want   int
	}{
		{"no session", nil, http.StatusUnauthorized},
		{"forged session", &http.Cookie{Name: auth.SessionCookie, Value: "forged"}, http.StatusUnauthorized},
		{"empty session", &http.Cookie{Name: auth.SessionCookie, Value: ""}, http.StatusUnauthorized},
		{"expired session", expired, http.StatusUnauthorized},
		{"login not on the allowlist", outsider, http.StatusForbidden},
	}
	for _, path := range dataPaths(f) {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, tc := range cases {
				request := httptest.NewRequest(method, path, nil)
				if tc.cookie != nil {
					request.AddCookie(tc.cookie)
				}
				recorder := serve(f, request)
				if recorder.Code != tc.want {
					t.Errorf("%s %s (%s): status %d, want %d", method, path, tc.name, recorder.Code, tc.want)
				}
				if leaksData(recorder.Body.String()) || recorder.Header().Get("Location") != "" {
					t.Errorf("%s %s (%s): response leaks data or redirects: %q", method, path, tc.name, recorder.Body.String())
				}
			}
		}
	}

	// The deployment smoke tests (deploy/deploy.sh SIGNIN_REFUSAL, and the CD
	// workflow) accept exactly this body as proof that the server, and not
	// some other 401, answered. Changing it means changing them too.
	recorder := serve(f, httptest.NewRequest(http.MethodGet, "/api/repos", nil))
	if got := strings.TrimRight(recorder.Body.String(), "\n"); recorder.Code != http.StatusUnauthorized ||
		got != `{"error":"authentication required"}` {
		t.Errorf("anonymous GET /api/repos = %d %q, want 401 with the exact sign-in refusal", recorder.Code, got)
	}

	// And a signed-in, allowed user does get through.
	request := httptest.NewRequest(http.MethodGet, "/api/repos?access=all", nil)
	request.AddCookie(f.session)
	if recorder := serve(f, request); recorder.Code != http.StatusOK || !leaksData(recorder.Body.String()) {
		t.Errorf("signed-in GET /api/repos = %d, want 200 with the repositories", recorder.Code)
	}
}

// Path tricks must end at the same check, never at data. The mux cleans paths
// by redirecting; following that redirect must still meet the sign-in check.
func TestAuthorizationBypassAttempts(t *testing.T) {
	f := newFixture(t)
	repo := jsonID(f.revoked.ID)
	paths := []string{
		"/api/repos/",
		"/api//repos",
		"/api/./repos",
		"/api/auth/../repos",
		"/api/auth/github/login/../../../repos",
		"/api/auth/github/callback/../../../repos/" + repo,
		"/api/auth/github/../../repos/" + repo + "/scans",
		"/healthz/../api/repos",
		"/webhooks/github/../../api/repos",
		"/api/repos/" + repo + "/../" + repo,
		"/API/repos",
		"/api/Repos",
		"/api/repos/" + repo + "%2fscans",
		"/api/repos%2F" + repo,
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		recorder := serve(f, request)
		for hops := 0; recorder.Code >= 300 && recorder.Code < 400 && hops < 5; hops++ {
			location := recorder.Header().Get("Location")
			if !strings.HasPrefix(location, "/") {
				t.Errorf("GET %s redirected off-site to %q", path, location)
				break
			}
			recorder = serve(f, httptest.NewRequest(http.MethodGet, location, nil))
		}
		if recorder.Code == http.StatusOK || leaksData(recorder.Body.String()) {
			t.Errorf("GET %s without a session = %d %q, want no data", path, recorder.Code, recorder.Body.String())
		}
	}

	// Headers that some frameworks treat as method or identity overrides.
	request := httptest.NewRequest(http.MethodGet, "/api/repos", nil)
	request.Header.Set("X-HTTP-Method-Override", "OPTIONS")
	request.Header.Set("X-Forwarded-User", "devmind2320")
	request.Header.Set("X-GitHub-Login", "devmind2320")
	request.Header.Set("Authorization", "Bearer devmind2320")
	if recorder := serve(f, request); recorder.Code != http.StatusUnauthorized {
		t.Errorf("override headers: status %d, want 401", recorder.Code)
	}
	// The session cookie under another name, or in a query string, is ignored.
	request = httptest.NewRequest(http.MethodGet, "/api/repos?"+auth.SessionCookie+"="+f.session.Value, nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: f.session.Value})
	if recorder := serve(f, request); recorder.Code != http.StatusUnauthorized {
		t.Errorf("misplaced session token: status %d, want 401", recorder.Code)
	}
}

// State-changing requests need the CSRF header and the dashboard's own Origin,
// and the check runs before sign-in, so a cross-site page learns nothing.
func TestStateChangingRequestsRequireSameOriginAndCSRFHeader(t *testing.T) {
	f := newFixture(t)
	repo := jsonID(f.active.ID)
	for _, path := range []string{"/api/auth/logout", "/api/repos/" + repo + "/scans", "/api/repos"} {
		for _, headers := range []map[string]string{
			{},
			{"Origin": testPublicURL},
			{auth.CSRFHeader: "1", "Origin": "https://evil.example"},
			{auth.CSRFHeader: "1", "Origin": "http://sbomdelta.test"},
		} {
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			request.AddCookie(f.session)
			for key, value := range headers {
				request.Header.Set(key, value)
			}
			if recorder := serve(f, request); recorder.Code != http.StatusForbidden {
				t.Errorf("POST %s with %v: status %d, want 403", path, headers, recorder.Code)
			}
		}
	}
	// None of those signed the user out.
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.AddCookie(f.session)
	if recorder := serve(f, request); recorder.Code != http.StatusOK {
		t.Errorf("session after refused requests: status %d, want 200", recorder.Code)
	}

	// Other unsafe methods are held to the same rule.
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request := httptest.NewRequest(method, "/api/repos/"+repo, nil)
		request.AddCookie(f.session)
		if recorder := serve(f, request); recorder.Code != http.StatusForbidden {
			t.Errorf("%s without CSRF header: status %d, want 403", method, recorder.Code)
		}
	}
}

// The webhook is exempt from the browser checks -- GitHub sends no Origin or
// CSRF header -- and is still served by the signature-verifying handler.
func TestWebhookBypassesBrowserChecksOnly(t *testing.T) {
	f := newFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(`{}`))
	if recorder := serve(f, request); recorder.Code != http.StatusAccepted || *f.webhookCalls != 1 {
		t.Errorf("webhook: status %d, calls %d; want the webhook handler to receive it", recorder.Code, *f.webhookCalls)
	}
}

func TestNoCORSHeaders(t *testing.T) {
	f := newFixture(t)
	preflight := httptest.NewRequest(http.MethodOptions, "/api/repos", nil)
	preflight.Header.Set("Origin", "https://evil.example")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", auth.CSRFHeader)

	get := httptest.NewRequest(http.MethodGet, "/api/repos", nil)
	get.Header.Set("Origin", "https://evil.example")
	get.AddCookie(f.session)

	for _, request := range []*http.Request{preflight, get} {
		recorder := serve(f, request)
		for key := range recorder.Header() {
			if strings.HasPrefix(strings.ToLower(key), "access-control-") {
				t.Errorf("%s %s sent %s: %q", request.Method, request.URL.Path, key, recorder.Header().Get(key))
			}
		}
	}
}

func TestHealthStaysPublic(t *testing.T) {
	f := newFixture(t)
	if recorder := serve(f, httptest.NewRequest(http.MethodGet, "/healthz", nil)); recorder.Code != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200 without signing in", recorder.Code)
	}
}
