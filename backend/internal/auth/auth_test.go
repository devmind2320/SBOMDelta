package auth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sbomdelta/internal/auth"
	"sbomdelta/internal/config"
	"sbomdelta/internal/storage"
	"sbomdelta/internal/storage/storagetest"
)

// Recognizable values, so a leak anywhere is easy to find.
const (
	userToken    = "ghu_UserTokenThatMustNeverLeak0000000"
	clientSecret = "client-secret-that-must-never-leak"
	clientID     = "Iv1.authtestclient"
	publicURL    = "https://sbomdelta.test"
)

// fakeGitHub serves the OAuth token exchange and GET /user.
type fakeGitHub struct {
	server *httptest.Server

	mu            sync.Mutex
	tokenRequests int
	tokenForm     url.Values
	tokenStatus   int
	tokenBody     string
	userStatus    int
	userBody      string

	// installations maps each installation the user can see to the
	// repositories they can reach in it, in GitHub's order. Both lists are
	// served 100 to a page, as GitHub does at per_page=100.
	installations   []fakeInstallation
	listStatus      int // when set, every listing request answers this
	listHeaders     map[string]string
	listPaths       []string // every listing request, path and query
	listAuthHeaders []string
}

type fakeInstallation struct {
	id    int64
	repos []fakeRepo
}

type fakeRepo struct {
	id      int64
	owner   string
	name    string
	private bool
}

// page returns items[(page-1)*perPage:page*perPage], clamped.
func page[T any](items []T, r *http.Request) []T {
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	number, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if perPage <= 0 || perPage > 100 {
		perPage = 30
	}
	if number <= 0 {
		number = 1
	}
	start := min((number-1)*perPage, len(items))
	return items[start:min(start+perPage, len(items))]
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{
		tokenStatus: http.StatusOK,
		tokenBody:   fmt.Sprintf(`{"access_token":%q,"token_type":"bearer","refresh_token":"ghr_refresh"}`, userToken),
		userStatus:  http.StatusOK,
		userBody:    `{"id":4001,"login":"DevMind2320","avatar_url":"https://avatars.example/u/4001"}`,
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login/oauth/access_token":
			f.tokenRequests++
			_ = r.ParseForm()
			f.tokenForm = r.PostForm
			w.WriteHeader(f.tokenStatus)
			_, _ = fmt.Fprint(w, f.tokenBody)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/user/installations"):
			f.listPaths = append(f.listPaths, r.URL.RequestURI())
			f.listAuthHeaders = append(f.listAuthHeaders, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer "+userToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			for key, value := range f.listHeaders {
				w.Header().Set(key, value)
			}
			if f.listStatus != 0 {
				w.WriteHeader(f.listStatus)
				_, _ = fmt.Fprint(w, `{"message":"listing refused"}`)
				return
			}
			if r.URL.Path == "/api/user/installations" {
				type installation struct {
					ID int64 `json:"id"`
				}
				all := make([]installation, 0, len(f.installations))
				for _, in := range f.installations {
					all = append(all, installation{ID: in.id})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(all), "installations": page(all, r)})
				return
			}
			for _, in := range f.installations {
				if r.URL.Path != fmt.Sprintf("/api/user/installations/%d/repositories", in.id) {
					continue
				}
				type owner struct {
					Login string `json:"login"`
				}
				type repo struct {
					ID            int64  `json:"id"`
					Name          string `json:"name"`
					Private       bool   `json:"private"`
					DefaultBranch string `json:"default_branch"`
					Owner         owner  `json:"owner"`
				}
				all := make([]repo, 0, len(in.repos))
				for _, rp := range in.repos {
					all = append(all, repo{ID: rp.id, Name: rp.name, Private: rp.private, DefaultBranch: "main", Owner: owner{Login: rp.owner}})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(all), "repositories": page(all, r)})
				return
			}
			http.NotFound(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/user":
			if r.Header.Get("Authorization") != "Bearer "+userToken {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
				return
			}
			w.WriteHeader(f.userStatus)
			_, _ = fmt.Fprint(w, f.userBody)
		default:
			t.Errorf("fake GitHub: unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

type harness struct {
	db      *storage.DB
	github  *fakeGitHub
	service *auth.Service
	logs    *bytes.Buffer
	handler http.Handler
}

func newHarness(t *testing.T, allowed ...string) *harness {
	t.Helper()
	db := storagetest.Open(t, "test_auth")
	github := newFakeGitHub(t)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if len(allowed) == 0 {
		allowed = []string{"devmind2320"}
	}
	public, _ := url.Parse(publicURL)
	service := auth.New(config.Auth{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		PublicURL:     public,
		WebBaseURL:    github.server.URL,
		AllowedLogins: allowed,
		SessionTTL:    time.Hour,
	}, github.server.URL+"/api/", db, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/github/login", service.Login)
	mux.HandleFunc("GET "+auth.CallbackPath, service.Callback)
	mux.HandleFunc("POST /api/auth/logout", service.Logout)
	mux.Handle("GET /api/me", service.RequireUser(http.HandlerFunc(service.Me)))
	return &harness{db: db, github: github, service: service, logs: logs, handler: service.SameOrigin(mux)}
}

func (h *harness) do(t *testing.T, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func cookieNamed(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// login starts the flow and returns the state the browser would carry back.
func (h *harness) login(t *testing.T) string {
	t.Helper()
	recorder := h.do(t, httptest.NewRequest(http.MethodGet, "/api/auth/github/login", nil))
	state := cookieNamed(recorder, auth.StateCookie)
	if state == nil || state.Value == "" {
		t.Fatal("login set no state cookie")
	}
	return state.Value
}

func (h *harness) callback(t *testing.T, query, stateCookie string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, auth.CallbackPath+"?"+query, nil)
	if stateCookie != "" {
		request.AddCookie(&http.Cookie{Name: auth.StateCookie, Value: stateCookie})
	}
	return h.do(t, request)
}

func (h *harness) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := h.db.Pool().QueryRow(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// signIn runs the whole flow and returns the session cookie.
func (h *harness) signIn(t *testing.T) *http.Cookie {
	t.Helper()
	state := h.login(t)
	recorder := h.callback(t, "code=good-code&state="+url.QueryEscape(state), state)
	session := cookieNamed(recorder, auth.SessionCookie)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/" || session == nil {
		t.Fatalf("sign-in: status %d, location %q, session cookie %v", recorder.Code, recorder.Header().Get("Location"), session)
	}
	return session
}

func (h *harness) me(t *testing.T, session *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	if session != nil {
		request.AddCookie(session)
	}
	return h.do(t, request)
}

func TestLoginRedirectsToGitHubWithState(t *testing.T) {
	h := newHarness(t)
	recorder := h.do(t, httptest.NewRequest(http.MethodGet, "/api/auth/github/login", nil))

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != h.github.server.URL+"/login/oauth/authorize" {
		t.Errorf("redirect = %q, want GitHub's authorize page", got)
	}
	query := location.Query()
	state := cookieNamed(recorder, auth.StateCookie)
	if state == nil {
		t.Fatal("no state cookie")
	}
	if query.Get("client_id") != clientID || query.Get("redirect_uri") != publicURL+auth.CallbackPath ||
		query.Get("state") != state.Value || len(state.Value) < 40 {
		t.Errorf("authorize query = %v, state cookie %q", query, state.Value)
	}
	if !state.HttpOnly || !state.Secure || state.SameSite != http.SameSiteLaxMode || state.Path != "/api/auth/github" || state.MaxAge != 600 {
		t.Errorf("state cookie = %+v, want HttpOnly, Secure, Lax, scoped to the auth path, 10 minutes", state)
	}
	if query.Get("client_secret") != "" || strings.Contains(location.String(), clientSecret) {
		t.Error("the authorize redirect carries the client secret")
	}
	if again := h.login(t); again == state.Value {
		t.Error("two logins produced the same state")
	}
}

// A callback that cannot prove it belongs to the login this browser started
// is refused before GitHub is asked anything.
func TestCallbackRejectsMissingOrMismatchedState(t *testing.T) {
	h := newHarness(t)
	state := h.login(t)
	tests := []struct {
		name   string
		query  string
		cookie string
	}{
		{"no state cookie", "code=c&state=" + state, ""},
		{"state does not match cookie", "code=c&state=forged", state},
		{"no state parameter", "code=c", state},
		{"empty cookie and parameter", "code=c&state=", ""},
		{"no code", "state=" + state, state},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := h.callback(t, tt.query, tt.cookie)
			if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login?error=state" {
				t.Errorf("status %d, location %q; want 303 to /login?error=state", recorder.Code, recorder.Header().Get("Location"))
			}
			if cookieNamed(recorder, auth.SessionCookie) != nil {
				t.Error("a session cookie was set")
			}
			cleared := cookieNamed(recorder, auth.StateCookie)
			if cleared == nil || cleared.MaxAge >= 0 {
				t.Error("the state cookie was not cleared")
			}
		})
	}
	if h.github.tokenRequests != 0 {
		t.Errorf("GitHub token requests = %d, want 0", h.github.tokenRequests)
	}
	if n := h.count(t, "sessions"); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

func TestCallbackWhenUserDeclines(t *testing.T) {
	h := newHarness(t)
	state := h.login(t)
	recorder := h.callback(t, "error=access_denied&state="+state, state)
	if recorder.Header().Get("Location") != "/login?error=denied" {
		t.Errorf("location = %q, want /login?error=denied", recorder.Header().Get("Location"))
	}
	if h.github.tokenRequests != 0 {
		t.Error("GitHub was asked for a token after the user declined")
	}
}

func TestCallbackSignsInAllowedUser(t *testing.T) {
	h := newHarness(t)
	session := h.signIn(t)

	form := h.github.tokenForm
	if form.Get("client_id") != clientID || form.Get("client_secret") != clientSecret ||
		form.Get("code") != "good-code" || form.Get("redirect_uri") != publicURL+auth.CallbackPath {
		t.Errorf("token exchange form = %v", form)
	}
	if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.MaxAge != 3600 {
		t.Errorf("session cookie = %+v, want HttpOnly, Secure, Lax, path /, the session TTL", session)
	}

	// Only the hash of the cookie is stored.
	sum := sha256.Sum256([]byte(session.Value))
	var stored int
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE token_hash = $1 AND expires_at > now() + interval '50 minutes'`, sum[:]).
		Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("sessions stored under the cookie's hash = %d (err %v), want 1", stored, err)
	}

	recorder := h.me(t, session)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/me status = %d, want 200", recorder.Code)
	}
	var me map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &me)
	if me["login"] != "DevMind2320" || me["authDisabled"] != false {
		t.Errorf("/api/me = %v", me)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Error("signed-in responses are cacheable")
	}
}

func TestCallbackRefusesAccountOutsideAllowlist(t *testing.T) {
	h := newHarness(t)
	h.github.userBody = `{"id":5002,"login":"someone-else"}`
	state := h.login(t)
	recorder := h.callback(t, "code=good-code&state="+state, state)

	if recorder.Header().Get("Location") != "/login?error=not_allowed" {
		t.Errorf("location = %q, want /login?error=not_allowed", recorder.Header().Get("Location"))
	}
	if cookieNamed(recorder, auth.SessionCookie) != nil {
		t.Error("a refused account got a session cookie")
	}
	if n := h.count(t, "sessions"); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
	if n := h.count(t, "users"); n != 0 {
		t.Errorf("users = %d, want 0: a refused account is not recorded", n)
	}
}

func TestCallbackGitHubFailures(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fakeGitHub)
		reason string
	}{
		{"code rejected", func(f *fakeGitHub) { f.tokenBody = `{"error":"bad_verification_code"}` }, "expired"},
		{"wrong client secret", func(f *fakeGitHub) { f.tokenBody = `{"error":"incorrect_client_credentials"}` }, "misconfigured"},
		{"callback URL not registered", func(f *fakeGitHub) { f.tokenBody = `{"error":"redirect_uri_mismatch"}` }, "misconfigured"},
		{"unverified email", func(f *fakeGitHub) { f.tokenBody = `{"error":"unverified_user_email"}` }, "unverified_email"},
		{"an error code GitHub adds later", func(f *fakeGitHub) { f.tokenBody = `{"error":"brand_new_error"}` }, "github"},
		{"token endpoint down", func(f *fakeGitHub) { f.tokenStatus = http.StatusBadGateway; f.tokenBody = `oops` }, "github"},
		{"no token and no error", func(f *fakeGitHub) { f.tokenBody = `{}` }, "github"},
		{"user endpoint refuses", func(f *fakeGitHub) { f.userStatus = http.StatusUnauthorized; f.userBody = `{}` }, "github"},
		{"user without id", func(f *fakeGitHub) { f.userBody = `{"login":"devmind2320"}` }, "github"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tt.setup(h.github)
			state := h.login(t)
			recorder := h.callback(t, "code=good-code&state="+state, state)
			if want := "/login?error=" + tt.reason; recorder.Header().Get("Location") != want {
				t.Errorf("location = %q, want %q", recorder.Header().Get("Location"), want)
			}
			if cookieNamed(recorder, auth.SessionCookie) != nil || h.count(t, "sessions") != 0 {
				t.Error("a failed sign-in produced a session")
			}
		})
	}
}

// GitHub's own words never reach the page or the logs: its error_description
// is free text, and an error code it has not documented is logged only as
// "unrecognized". The sign-in page gets one of a fixed set of reasons.
func TestGitHubErrorTextIsNeverEchoed(t *testing.T) {
	const crafted = "<script>alert(1)</script> visit evil.example"
	h := newHarness(t)
	h.github.tokenBody = fmt.Sprintf(`{"error":%q,"error_description":%q}`, crafted, crafted)
	state := h.login(t)
	recorder := h.callback(t, "code=good-code&state="+state, state)
	if got := recorder.Header().Get("Location"); got != "/login?error=github" {
		t.Errorf("token refusal: location = %q, want /login?error=github", got)
	}

	state = h.login(t)
	recorder = h.callback(t, "error="+url.QueryEscape(crafted)+"&error_description="+url.QueryEscape(crafted)+"&state="+state, state)
	if got := recorder.Header().Get("Location"); got != "/login?error=github" {
		t.Errorf("callback error: location = %q, want /login?error=github", got)
	}
	if strings.Contains(h.logs.String(), "evil.example") || strings.Contains(recorder.Body.String(), "evil.example") {
		t.Errorf("GitHub's error text was echoed; logs:\n%s", h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "unrecognized") {
		t.Error("the unrecognized error codes were not logged as such")
	}
}

func TestCallbackExplainsKnownAuthorizationErrors(t *testing.T) {
	for code, reason := range map[string]string{
		"access_denied":         "denied",
		"redirect_uri_mismatch": "misconfigured",
		"application_suspended": "suspended",
		"something_else":        "github",
	} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t)
			state := h.login(t)
			recorder := h.callback(t, "error="+code+"&state="+state, state)
			if want := "/login?error=" + reason; recorder.Header().Get("Location") != want {
				t.Errorf("location = %q, want %q", recorder.Header().Get("Location"), want)
			}
			if h.github.tokenRequests != 0 || cookieNamed(recorder, auth.SessionCookie) != nil {
				t.Error("a GitHub authorization error still led to a token request or a session")
			}
		})
	}
}

// Signing in again from a browser that still has a session replaces that
// session instead of leaving it valid until it expires.
func TestSigningInAgainReplacesThePreviousSession(t *testing.T) {
	h := newHarness(t)
	first := h.signIn(t)

	state := h.login(t)
	request := httptest.NewRequest(http.MethodGet, auth.CallbackPath+"?code=good-code&state="+url.QueryEscape(state), nil)
	request.AddCookie(&http.Cookie{Name: auth.StateCookie, Value: state})
	request.AddCookie(first)
	recorder := h.do(t, request)
	second := cookieNamed(recorder, auth.SessionCookie)
	if second == nil || second.Value == first.Value {
		t.Fatalf("second sign-in: status %d, session cookie %v", recorder.Code, second)
	}
	if code := h.me(t, first).Code; code != http.StatusUnauthorized {
		t.Errorf("the replaced session: status %d, want 401", code)
	}
	if code := h.me(t, second).Code; code != http.StatusOK {
		t.Errorf("the new session: status %d, want 200", code)
	}
	if n := h.count(t, "sessions"); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
}

func TestRequireUserRejectsMissingForgedAndExpiredSessions(t *testing.T) {
	h := newHarness(t)
	session := h.signIn(t)

	if code := h.me(t, nil).Code; code != http.StatusUnauthorized {
		t.Errorf("no cookie: status %d, want 401", code)
	}
	if code := h.me(t, &http.Cookie{Name: auth.SessionCookie, Value: "forged"}).Code; code != http.StatusUnauthorized {
		t.Errorf("forged cookie: status %d, want 401", code)
	}
	// The stored hash itself is not a valid cookie.
	sum := sha256.Sum256([]byte(session.Value))
	hashCookie := &http.Cookie{Name: auth.SessionCookie, Value: fmt.Sprintf("%x", sum)}
	if code := h.me(t, hashCookie).Code; code != http.StatusUnauthorized {
		t.Errorf("hash as cookie: status %d, want 401", code)
	}

	if _, err := h.db.Pool().Exec(context.Background(), `UPDATE sessions SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code := h.me(t, session).Code; code != http.StatusUnauthorized {
		t.Errorf("expired session: status %d, want 401", code)
	}
}

// Removing someone from ALLOWED_GITHUB_LOGINS cuts off sessions they already
// have, not just future sign-ins.
func TestRequireUserRechecksAllowlist(t *testing.T) {
	h := newHarness(t)
	session := h.signIn(t)

	// The same database, with a server restarted on a narrower allowlist.
	public, _ := url.Parse(publicURL)
	narrowed := auth.New(config.Auth{
		ClientID: clientID, ClientSecret: clientSecret, PublicURL: public,
		WebBaseURL: h.github.server.URL, AllowedLogins: []string{"someone-else"}, SessionTTL: time.Hour,
	}, h.github.server.URL+"/api/", h.db, slog.New(slog.DiscardHandler))
	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.AddCookie(session)
	recorder := httptest.NewRecorder()
	narrowed.RequireUser(http.HandlerFunc(narrowed.Me)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a login removed from the allowlist", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "DevMind2320") {
		t.Error("the refused response still describes the user")
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	session := h.signIn(t)

	request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	request.Header.Set(auth.CSRFHeader, "1")
	request.Header.Set("Origin", publicURL)
	request.AddCookie(session)
	recorder := h.do(t, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", recorder.Code)
	}
	if cleared := cookieNamed(recorder, auth.SessionCookie); cleared == nil || cleared.MaxAge >= 0 {
		t.Error("logout did not clear the session cookie")
	}
	if code := h.me(t, session).Code; code != http.StatusUnauthorized {
		t.Errorf("after logout: status %d, want 401", code)
	}
	if n := h.count(t, "sessions"); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}
}

// A sign-out that could not delete the session says so and keeps the cookie:
// clearing only the cookie would look signed out while the session stayed
// valid for anyone holding its token.
func TestLogoutFailureIsReportedAndKeepsTheSession(t *testing.T) {
	h := newHarness(t)
	session := h.signIn(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the database call fails, as it would with the database down
	request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil).WithContext(ctx)
	request.Header.Set(auth.CSRFHeader, "1")
	request.Header.Set("Origin", publicURL)
	request.AddCookie(session)
	recorder := h.do(t, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "could not sign out") {
		t.Errorf("body = %q, want it to say sign-out failed", recorder.Body.String())
	}
	if cookieNamed(recorder, auth.SessionCookie) != nil {
		t.Error("the cookie was cleared although the session still exists")
	}
	if code := h.me(t, session).Code; code != http.StatusOK {
		t.Errorf("the session after a failed sign-out: status %d, want 200 (still signed in, and told so)", code)
	}
}

func TestSameOriginGuardsStateChangingRequests(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"no CSRF header", map[string]string{"Origin": publicURL}, http.StatusForbidden},
		{"CSRF header from another origin", map[string]string{auth.CSRFHeader: "1", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"CSRF header from a lookalike origin", map[string]string{auth.CSRFHeader: "1", "Origin": publicURL + ".evil.example"}, http.StatusForbidden},
		{"opaque origin", map[string]string{auth.CSRFHeader: "1", "Origin": "null"}, http.StatusForbidden},
		{"no origin, cross-site fetch metadata", map[string]string{auth.CSRFHeader: "1", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"wrong CSRF header value", map[string]string{auth.CSRFHeader: "true", "Origin": publicURL}, http.StatusForbidden},
		{"same origin with header", map[string]string{auth.CSRFHeader: "1", "Origin": publicURL}, http.StatusNoContent},
		{"no origin, same-origin fetch metadata", map[string]string{auth.CSRFHeader: "1", "Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
			for key, value := range tt.headers {
				request.Header.Set(key, value)
			}
			// A fresh session each time, so a refused request is seen to
			// leave it alive.
			fresh := h.signIn(t)
			request.AddCookie(fresh)
			recorder := h.do(t, request)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
			alive := h.me(t, fresh).Code == http.StatusOK
			if alive != (tt.want != http.StatusNoContent) {
				t.Errorf("session alive after the request = %v", alive)
			}
		})
	}
}

// Neither the user's GitHub token nor the client secret may reach a log line,
// a response, a cookie or a database row, on success or on failure.
func TestTokensAndSecretsNeverLeak(t *testing.T) {
	h := newHarness(t)
	h.github.installations = []fakeInstallation{{id: 31, repos: []fakeRepo{{id: 1, owner: "devmind2320", name: "api", private: true}}}}
	var responses strings.Builder
	record := func(recorder *httptest.ResponseRecorder) {
		responses.WriteString(recorder.Body.String())
		for key, values := range recorder.Header() {
			responses.WriteString(key + ": " + strings.Join(values, ",") + "\n")
		}
	}

	state := h.login(t)
	success := h.callback(t, "code=good-code&state="+state, state)
	record(success)
	session := cookieNamed(success, auth.SessionCookie)
	record(h.me(t, session))

	// A listing GitHub refuses after the token was issued.
	h.github.listStatus = http.StatusInternalServerError
	state = h.login(t)
	record(h.callback(t, "code=good-code&state="+state, state))
	h.github.listStatus = 0

	// Failures after GitHub has issued a token: refused account, /user error.
	h.github.userBody = `{"id":5002,"login":"someone-else"}`
	state = h.login(t)
	record(h.callback(t, "code=good-code&state="+state, state))
	h.github.userStatus = http.StatusInternalServerError
	state = h.login(t)
	record(h.callback(t, "code=good-code&state="+state, state))
	// A token endpoint that echoes what it was sent.
	h.github.tokenStatus = http.StatusBadRequest
	h.github.tokenBody = fmt.Sprintf(`{"error":"incorrect_client_credentials","error_description":"bad secret %s"}`, clientSecret)
	state = h.login(t)
	record(h.callback(t, "code=good-code&state="+state, state))

	var rows strings.Builder
	for _, table := range []string{"users", "sessions", "user_repositories"} {
		dbRows, err := h.db.Pool().Query(context.Background(), `SELECT row_to_json(t)::text FROM `+table+` t`)
		if err != nil {
			t.Fatal(err)
		}
		for dbRows.Next() {
			var row string
			_ = dbRows.Scan(&row)
			rows.WriteString(row + "\n")
		}
		dbRows.Close()
	}

	for name, haystack := range map[string]string{
		"logs":           h.logs.String(),
		"responses":      responses.String(),
		"session cookie": session.Value,
		"database rows":  rows.String(),
	} {
		for _, secret := range []string{userToken, "ghr_refresh", clientSecret} {
			if strings.Contains(haystack, secret) {
				t.Errorf("%s contain %q", name, secret)
			}
		}
	}
	if strings.Contains(rows.String(), session.Value) {
		t.Error("the database holds the raw session token")
	}
	if !strings.Contains(h.logs.String(), "incorrect_client_credentials") {
		t.Error("the token exchange failure reason was not logged at all")
	}
}

func TestDisabledSignInTreatsRequestsAsDevelopmentUser(t *testing.T) {
	db := storagetest.Open(t, "test_auth")
	service := auth.New(config.Auth{Disabled: true}, "https://api.github.test/", db, slog.New(slog.DiscardHandler))
	handler := service.RequireUser(http.HandlerFunc(service.Me))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"authDisabled":true`) {
		t.Errorf("status %d, body %s", recorder.Code, recorder.Body.String())
	}
}

type storedRepository struct {
	githubRepoID, installationID int64
	fullName                     string
	private                      bool
}

func (h *harness) storedRepositories(t *testing.T) []storedRepository {
	t.Helper()
	rows, err := h.db.Pool().Query(context.Background(), `
		SELECT github_repo_id, github_installation_id, owner || '/' || name, private
		FROM user_repositories ORDER BY github_repo_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []storedRepository
	for rows.Next() {
		var repo storedRepository
		if err := rows.Scan(&repo.githubRepoID, &repo.installationID, &repo.fullName, &repo.private); err != nil {
			t.Fatal(err)
		}
		out = append(out, repo)
	}
	return out
}

func (h *harness) listing(t *testing.T) (*time.Time, string) {
	t.Helper()
	var listedAt *time.Time
	var reason *string
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT repos_listed_at, repos_list_error FROM users`).Scan(&listedAt, &reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return listedAt, ""
	}
	return listedAt, *reason
}

// Signing in records every repository the user can reach through the App's
// installations, paging through each list to its end and no further.
func TestSignInRecordsRepositoriesAcrossPages(t *testing.T) {
	h := newHarness(t)
	big := make([]fakeRepo, 0, 250)
	for i := range 250 {
		big = append(big, fakeRepo{id: int64(10000 + i), owner: "acme", name: fmt.Sprintf("svc-%03d", i), private: i%2 == 0})
	}
	h.github.installations = []fakeInstallation{
		{id: 31, repos: big},
		{id: 32, repos: []fakeRepo{{id: 7, owner: "devmind2320", name: "SBOMDelta", private: true}}},
	}
	h.signIn(t)

	stored := h.storedRepositories(t)
	if len(stored) != 251 {
		t.Fatalf("stored %d repositories, want all 251", len(stored))
	}
	if stored[0] != (storedRepository{7, 32, "devmind2320/SBOMDelta", true}) {
		t.Errorf("first stored = %+v, want SBOMDelta from installation 32", stored[0])
	}
	if last := stored[250]; last != (storedRepository{10249, 31, "acme/svc-249", false}) {
		t.Errorf("last stored = %+v, want the last repository of page 3", last)
	}

	want := []string{
		"/api/user/installations?per_page=100&page=1",
		"/api/user/installations/31/repositories?per_page=100&page=1",
		"/api/user/installations/31/repositories?per_page=100&page=2",
		"/api/user/installations/31/repositories?per_page=100&page=3",
		"/api/user/installations/32/repositories?per_page=100&page=1",
	}
	if strings.Join(h.github.listPaths, "\n") != strings.Join(want, "\n") {
		t.Errorf("listing requests:\n%s\nwant:\n%s", strings.Join(h.github.listPaths, "\n"), strings.Join(want, "\n"))
	}
	for _, header := range h.github.listAuthHeaders {
		if header != "Bearer "+userToken {
			t.Errorf("a listing request was not made with the user's token")
		}
	}
	if listedAt, reason := h.listing(t); listedAt == nil || reason != "" {
		t.Errorf("listing = %v %q, want a time and no error", listedAt, reason)
	}
}

// Each sign-in replaces the list: a repository the user lost access to on
// GitHub is no longer theirs in SBOMDelta.
func TestSignInReplacesTheRepositoryList(t *testing.T) {
	h := newHarness(t)
	h.github.installations = []fakeInstallation{{id: 31, repos: []fakeRepo{
		{id: 1, owner: "devmind2320", name: "api"}, {id: 2, owner: "devmind2320", name: "web"},
	}}}
	h.signIn(t)
	h.github.installations[0].repos = h.github.installations[0].repos[1:]
	h.signIn(t)

	stored := h.storedRepositories(t)
	if len(stored) != 1 || stored[0].fullName != "devmind2320/web" {
		t.Errorf("stored = %+v, want only devmind2320/web", stored)
	}
}

// GitHub refusing the listing does not refuse the sign-in -- the user gets a
// session and can retry -- but the old list is cleared, never kept stale,
// and the reason is recorded as a fixed code.
func TestSignInSurvivesARefusedRepositoryListing(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		reason  string
	}{
		{"rate limited", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, auth.ListErrorRateLimited},
		{"too many requests", http.StatusTooManyRequests, nil, auth.ListErrorRateLimited},
		{"authorization revoked", http.StatusUnauthorized, nil, auth.ListErrorUnauthorized},
		{"forbidden", http.StatusForbidden, nil, auth.ListErrorGitHub},
		{"GitHub error", http.StatusBadGateway, nil, auth.ListErrorGitHub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.github.installations = []fakeInstallation{{id: 31, repos: []fakeRepo{{id: 1, owner: "devmind2320", name: "api"}}}}
			h.signIn(t)

			h.github.listStatus, h.github.listHeaders = tt.status, tt.headers
			session := h.signIn(t)
			if code := h.me(t, session).Code; code != http.StatusOK {
				t.Errorf("session after a refused listing: status %d, want 200", code)
			}
			if stored := h.storedRepositories(t); len(stored) != 0 {
				t.Errorf("stored = %+v, want the stale list cleared", stored)
			}
			if _, reason := h.listing(t); reason != tt.reason {
				t.Errorf("reason = %q, want %q", reason, tt.reason)
			}
			if strings.Contains(h.logs.String(), "listing refused") {
				t.Error("GitHub's response body reached the logs")
			}
		})
	}
}
