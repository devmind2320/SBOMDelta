// Package auth signs people in to the dashboard with the GitHub App's user
// authorization flow and guards the API behind those sessions.
//
// Signing in proves who someone is; it grants nothing on GitHub. The user's
// token is used once, to read their identity, and then discarded. Repository
// access, cloning and scanning still go through installation tokens only.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"sbomdelta/internal/config"
	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
)

const (
	// SessionCookie holds the session token. HttpOnly: page scripts never see it.
	SessionCookie = "sbomdelta_session"
	// StateCookie carries the OAuth state from the login redirect to the
	// callback, binding the callback to the browser that started it.
	StateCookie = "sbomdelta_oauth_state"
	// CSRFHeader must accompany every state-changing request. A cross-site
	// form cannot set a custom header, and a cross-site script cannot send one
	// without a CORS preflight, which this API never approves.
	CSRFHeader = "X-SBOMDelta-Request"

	// CallbackPath sits under /api so that the proxies already in front of
	// the API (Vite in development, Nginx in production) route it unchanged.
	CallbackPath = "/api/auth/github/callback"
	statePath    = "/api/auth/github"
	stateTTL     = 10 * time.Minute
	tokenBytes   = 32
)

// Service signs people in and out and checks every API request.
type Service struct {
	cfg     config.Auth
	db      *storage.DB
	client  *http.Client
	apiBase string
	logger  *slog.Logger
	// listed, when set, is told which installations a sign-in's repository
	// listing reached, once that listing is stored.
	listed func(ctx context.Context, githubInstallationIDs []int64) error
}

// New builds the service. apiBaseURL is the GitHub REST API root used to read
// the signed-in user (api.github.com, or a GitHub Enterprise Server API).
func New(cfg config.Auth, apiBaseURL string, db *storage.DB, logger *slog.Logger) *Service {
	return &Service{
		cfg:     cfg,
		db:      db,
		client:  &http.Client{Timeout: 15 * time.Second},
		apiBase: strings.TrimRight(apiBaseURL, "/"),
		logger:  logger,
	}
}

// OnInstallationsListed registers fn to run after each sign-in stores the
// user's repository list, with the installations that list reached. A failure
// is logged and does not fail the sign-in.
func (s *Service) OnInstallationsListed(fn func(ctx context.Context, githubInstallationIDs []int64) error) {
	s.listed = fn
}

// developmentUser stands in for a signed-in person when AUTH_DISABLED is set,
// which configuration allows only in development.
var developmentUser = models.User{Login: "development"}

type contextKey struct{}

// UserFrom returns the signed-in user RequireUser attached to the request.
func UserFrom(ctx context.Context) (models.User, bool) {
	user, ok := ctx.Value(contextKey{}).(models.User)
	return user, ok
}

// HashToken is how a session token is stored: a database copy of the sessions
// table holds only hashes and cannot be replayed as cookies.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func newToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// allowed reports whether login may sign in: any login unless
// ALLOWED_GITHUB_LOGINS restricts sign-in.
func (s *Service) allowed(login string) bool {
	return len(s.cfg.AllowedLogins) == 0 || slices.Contains(s.cfg.AllowedLogins, strings.ToLower(login))
}

func (s *Service) callbackURL() string {
	return s.cfg.PublicURL.String() + CallbackPath
}

func (s *Service) cookie(name, value, path string, maxAge time.Duration) *http.Cookie {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		cookie.MaxAge = int(maxAge.Seconds())
	} else {
		cookie.MaxAge = -1
	}
	return cookie
}

// GitHub reports failures with documented error codes: on the callback when
// the authorization itself fails, and from the token endpoint when the code
// cannot be exchanged. The ones a person can act on get their own reason on
// the sign-in page; anything else is "github". GitHub's free-text
// error_description is never shown or logged.
var (
	callbackErrors = map[string]string{
		"access_denied":         "denied",
		"redirect_uri_mismatch": "misconfigured",
		"application_suspended": "suspended",
	}
	tokenErrors = map[string]string{
		"bad_verification_code":        "expired",
		"incorrect_client_credentials": "misconfigured",
		"redirect_uri_mismatch":        "misconfigured",
		"unverified_user_email":        "unverified_email",
	}
)

// tokenError is a refusal from GitHub's token endpoint. Code is GitHub's
// error code, which carries no secret.
type tokenError struct {
	status int
	code   string
}

func (e *tokenError) Error() string {
	return fmt.Sprintf("token exchange refused (HTTP %d): %s", e.status, e.code)
}

// knownCode returns code if it is one of the documented codes in reasons, so
// that only those reach the logs verbatim.
func knownCode(code string, reasons map[string]string) string {
	if _, ok := reasons[code]; ok {
		return code
	}
	return "unrecognized"
}

// redirectToLogin sends the browser back to the sign-in page with a reason it
// can show. The reason is one of a fixed set of codes, never error text.
func redirectToLogin(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(reason), http.StatusSeeOther)
}

// Login starts the GitHub authorization flow.
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Disabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	state, err := newToken()
	if err != nil {
		s.logger.Error("could not start sign-in", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, s.cookie(StateCookie, state, statePath, stateTTL))

	query := url.Values{
		"client_id":    {s.cfg.ClientID},
		"redirect_uri": {s.callbackURL()},
		"state":        {state},
	}
	http.Redirect(w, r, s.cfg.WebBaseURL+"/login/oauth/authorize?"+query.Encode(), http.StatusFound)
}

// Callback completes the flow GitHub redirects back to. Every failure ends on
// the sign-in page without a session.
func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Disabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// The state is single use whatever happens next.
	http.SetCookie(w, s.cookie(StateCookie, "", statePath, 0))

	query := r.URL.Query()
	if code := query.Get("error"); code != "" {
		// GitHub could not authorize: most often the person declined on the
		// consent page (access_denied).
		reason, ok := callbackErrors[code]
		if !ok {
			reason = "github"
		}
		s.logger.Warn("GitHub returned a sign-in error", "github_error", knownCode(code, callbackErrors))
		redirectToLogin(w, r, reason)
		return
	}
	stateCookie, err := r.Cookie(StateCookie)
	state := query.Get("state")
	if err != nil || state == "" || stateCookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		s.logger.Warn("rejected sign-in callback with a missing or mismatched state")
		redirectToLogin(w, r, "state")
		return
	}
	code := query.Get("code")
	if code == "" {
		redirectToLogin(w, r, "state")
		return
	}

	token, err := s.exchange(r.Context(), code)
	if err != nil {
		reason := "github"
		var refused *tokenError
		if errors.As(err, &refused) {
			if mapped, ok := tokenErrors[refused.code]; ok {
				reason = mapped
			}
			err = &tokenError{status: refused.status, code: knownCode(refused.code, tokenErrors)}
		}
		s.logger.Warn("could not complete sign-in with GitHub", "error", err)
		redirectToLogin(w, r, reason)
		return
	}
	identity, err := s.fetchUser(r.Context(), token)
	if err != nil {
		s.logger.Warn("could not read the signed-in GitHub user", "error", err)
		redirectToLogin(w, r, "github")
		return
	}
	if !s.allowed(identity.Login) {
		s.logger.Warn("refused sign-in from a GitHub account outside ALLOWED_GITHUB_LOGINS",
			"login", identity.Login, "github_user_id", identity.GitHubUserID)
		redirectToLogin(w, r, "not_allowed")
		return
	}

	user, err := s.db.UpsertUser(r.Context(), identity)
	if err != nil {
		s.logger.Error("could not record the signed-in user", "error", err)
		redirectToLogin(w, r, "server")
		return
	}
	// The token is still in hand, so this is the moment to learn which
	// repositories the user can reach; after this it is discarded.
	if err := s.recordRepositories(r.Context(), user, token); err != nil {
		s.logger.Error("could not record the user's repositories", "error", err)
		redirectToLogin(w, r, "server")
		return
	}
	// Signing in again from the same browser replaces its session rather
	// than leaving the old one valid until it expires.
	if previous, err := r.Cookie(SessionCookie); err == nil && previous.Value != "" {
		if err := s.db.DeleteSession(r.Context(), HashToken(previous.Value)); err != nil {
			s.logger.Error("could not end the previous session", "error", err)
			redirectToLogin(w, r, "server")
			return
		}
	}
	session, err := newToken()
	if err != nil {
		s.logger.Error("could not create a session", "error", err)
		redirectToLogin(w, r, "server")
		return
	}
	if err := s.db.CreateSession(r.Context(), HashToken(session), user.ID, time.Now().Add(s.cfg.SessionTTL)); err != nil {
		s.logger.Error("could not create a session", "error", err)
		redirectToLogin(w, r, "server")
		return
	}
	http.SetCookie(w, s.cookie(SessionCookie, session, "/", s.cfg.SessionTTL))
	s.logger.Info("signed in", "login", user.Login, "github_user_id", user.GitHubUserID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Logout ends the session. It is a POST, so SameOrigin has already checked
// the CSRF header and Origin before this runs.
//
// If the session cannot be deleted, the cookie is kept and the failure
// reported: clearing only the cookie would look like signing out while the
// session stayed valid for anyone holding its token.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookie); err == nil && cookie.Value != "" {
		if err := s.db.DeleteSession(r.Context(), HashToken(cookie.Value)); err != nil {
			s.logger.Error("could not delete session", "error", err)
			writeError(w, http.StatusInternalServerError, "could not sign out; please try again")
			return
		}
	}
	http.SetCookie(w, s.cookie(SessionCookie, "", "/", 0))
	w.WriteHeader(http.StatusNoContent)
}

// Me reports who is signed in. It runs behind RequireUser.
func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"login":        user.Login,
		"avatarUrl":    user.AvatarURL,
		"authDisabled": s.cfg.Disabled,
		"installUrl":   s.cfg.InstallURL,
	})
}

// RequireUser admits only requests carrying a live session for an allowed
// login. When ALLOWED_GITHUB_LOGINS restricts sign-in it is checked on every
// request, not just at sign-in, so removing a login cuts off its existing
// sessions.
func (s *Service) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Responses behind sign-in must never be served from a shared cache.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Cookie")

		if s.cfg.Disabled {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, developmentUser)))
			return
		}
		cookie, err := r.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		user, err := s.db.SessionUser(r.Context(), HashToken(cookie.Value))
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if err != nil {
			s.logger.Error("could not check session", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !s.allowed(user.Login) {
			writeError(w, http.StatusForbidden, "this GitHub account is not allowed to use this dashboard")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, user)))
	})
}

// SameOrigin rejects state-changing requests that did not come from the
// dashboard itself: they must carry the CSRF header and an Origin equal to
// PUBLIC_URL. Safe methods pass, and so does the GitHub webhook, which
// proves itself with its HMAC signature instead.
func (s *Service) SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/webhooks/github" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(CSRFHeader) != "1" {
			writeError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		if !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) sameOrigin(r *http.Request) bool {
	if s.cfg.Disabled && s.cfg.PublicURL == nil {
		// Local development without sign-in has no configured origin; the
		// header check still stands.
		return r.Header.Get("Origin") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == s.cfg.PublicURL.String()
	}
	// Browsers send Origin on every cross-origin POST; one without it is either
	// same-origin or not a browser. Fetch metadata settles which, when present.
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// exchange trades the authorization code for a user token. Neither the token
// nor the client secret ever appears in an error.
func (s *Service) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {s.cfg.ClientID},
		"client_secret": {s.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {s.callbackURL()},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.WebBaseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", stripURL(err))
	}
	defer response.Body.Close()

	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil {
		return "", fmt.Errorf("token response (HTTP %d) was not JSON", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK || body.AccessToken == "" {
		code := body.Error
		if code == "" {
			code = "no access token"
		}
		return "", &tokenError{status: response.StatusCode, code: code}
	}
	return body.AccessToken, nil
}

// fetchUser reads the identity behind a user token.
func (s *Service) fetchUser(ctx context.Context, token string) (models.User, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiBase+"/user", nil)
	if err != nil {
		return models.User{}, fmt.Errorf("build user request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := s.client.Do(request)
	if err != nil {
		return models.User{}, fmt.Errorf("user request failed: %w", stripURL(err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return models.User{}, fmt.Errorf("user request returned HTTP %d", response.StatusCode)
	}

	var body struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body); err != nil {
		return models.User{}, errors.New("user response was not JSON")
	}
	if body.ID == 0 || body.Login == "" {
		return models.User{}, errors.New("user response had no id or login")
	}
	return models.User{GitHubUserID: body.ID, Login: body.Login, AvatarURL: body.AvatarURL}, nil
}

// Listing limits. GitHub pages at most 100 entries; 100 pages of each list is
// 10,000 installations or repositories per installation, far past any account
// this dashboard serves, and keeps a sign-in from paging forever.
const (
	listPageSize = 100
	maxListPages = 100
	listTimeout  = 60 * time.Second
)

// Reasons a repository list could not be read, stored on the user and shown
// on the dashboard. Fixed codes, never GitHub's text.
const (
	ListErrorUnauthorized = "unauthorized"
	ListErrorRateLimited  = "rate_limited"
	ListErrorGitHub       = "github"
	ListErrorTooMany      = "too_many"
)

// listError is a failed repository listing, with the code recorded for it.
type listError struct {
	code   string
	detail string
}

func (e *listError) Error() string { return e.code + ": " + e.detail }

// recordRepositories asks GitHub which repositories the user can reach
// through the App's installations and records that list as what the user may
// see and scan. A listing GitHub refuses or fails is recorded as such, with
// an empty list -- the user is still signed in and can retry -- but a
// database failure fails the sign-in.
func (s *Service) recordRepositories(ctx context.Context, user models.User, token string) error {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()

	repos, err := s.listAccessibleRepositories(ctx, token)
	if err != nil {
		code := ListErrorGitHub
		var failed *listError
		if errors.As(err, &failed) {
			code = failed.code
		}
		s.logger.Warn("could not list the user's repositories from GitHub",
			"login", user.Login, "reason", code, "error", err)
		return s.db.ClearUserRepositories(context.WithoutCancel(ctx), user.ID, code, time.Now())
	}
	s.logger.Info("listed the user's repositories", "login", user.Login, "repositories", len(repos))
	if err := s.db.ReplaceUserRepositories(context.WithoutCancel(ctx), user.ID, repos, time.Now()); err != nil {
		return err
	}
	if s.listed != nil {
		var installations []int64
		for _, repo := range repos {
			if !slices.Contains(installations, repo.GitHubInstallationID) {
				installations = append(installations, repo.GitHubInstallationID)
			}
		}
		if err := s.listed(context.WithoutCancel(ctx), installations); err != nil {
			s.logger.Warn("could not queue reconciliation of the user's installations",
				"login", user.Login, "error", err)
		}
	}
	return nil
}

// listAccessibleRepositories pages through the installations the user can
// see and, for each, the repositories the user can reach in it. Together
// these are exactly the repositories both the user and the App have access
// to, which is what GitHub App user tokens are scoped to.
func (s *Service) listAccessibleRepositories(ctx context.Context, token string) ([]models.AccessibleRepository, error) {
	var installations []int64
	err := s.paginate(ctx, token, "/user/installations", func(body []byte) (int, int, error) {
		var page struct {
			TotalCount    int `json:"total_count"`
			Installations []struct {
				ID int64 `json:"id"`
			} `json:"installations"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, 0, errors.New("installations response was not JSON")
		}
		for _, installation := range page.Installations {
			if installation.ID != 0 {
				installations = append(installations, installation.ID)
			}
		}
		return len(page.Installations), page.TotalCount, nil
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[int64]bool)
	repos := make([]models.AccessibleRepository, 0)
	for _, installationID := range installations {
		path := fmt.Sprintf("/user/installations/%d/repositories", installationID)
		err := s.paginate(ctx, token, path, func(body []byte) (int, int, error) {
			var page struct {
				TotalCount   int `json:"total_count"`
				Repositories []struct {
					ID            int64  `json:"id"`
					Name          string `json:"name"`
					Private       bool   `json:"private"`
					DefaultBranch string `json:"default_branch"`
					Owner         struct {
						Login string `json:"login"`
					} `json:"owner"`
				} `json:"repositories"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return 0, 0, errors.New("repositories response was not JSON")
			}
			for _, repo := range page.Repositories {
				if repo.ID == 0 || repo.Name == "" || repo.Owner.Login == "" || seen[repo.ID] {
					continue
				}
				seen[repo.ID] = true
				repos = append(repos, models.AccessibleRepository{
					GitHubRepoID: repo.ID, GitHubInstallationID: installationID,
					Owner: repo.Owner.Login, Name: repo.Name, Private: repo.Private, DefaultBranch: repo.DefaultBranch,
				})
			}
			return len(page.Repositories), page.TotalCount, nil
		})
		if err != nil {
			return nil, err
		}
	}
	return repos, nil
}

// paginate GETs path page by page, handing each body to read, which returns
// how many entries the page held and the total GitHub reported. It stops at
// a short page or once the total is reached, and refuses to go past
// maxListPages rather than return a silently truncated list.
func (s *Service) paginate(ctx context.Context, token, path string, read func([]byte) (int, int, error)) error {
	seen := 0
	for page := 1; ; page++ {
		if page > maxListPages {
			return &listError{code: ListErrorTooMany, detail: path + " has more than " + fmt.Sprint(maxListPages*listPageSize) + " entries"}
		}
		body, err := s.githubGet(ctx, token, fmt.Sprintf("%s?per_page=%d&page=%d", path, listPageSize, page))
		if err != nil {
			return err
		}
		count, total, err := read(body)
		if err != nil {
			return &listError{code: ListErrorGitHub, detail: err.Error()}
		}
		seen += count
		if count < listPageSize || (total > 0 && seen >= total) {
			return nil
		}
	}
}

// githubGet makes one authenticated GET to the GitHub API and classifies a
// refusal. Errors name the path and status only: never the token, never the
// response body.
func (s *Service) githubGet(ctx context.Context, token, pathAndQuery string) ([]byte, error) {
	path := pathAndQuery
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiBase+pathAndQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", path, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, &listError{code: ListErrorGitHub, detail: path + ": " + stripURL(err).Error()}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, &listError{code: ListErrorGitHub, detail: path + ": reading the response failed"}
	}
	switch {
	case response.StatusCode == http.StatusOK:
		return body, nil
	case response.StatusCode == http.StatusUnauthorized:
		return nil, &listError{code: ListErrorUnauthorized, detail: path + " returned HTTP 401"}
	case response.StatusCode == http.StatusTooManyRequests ||
		(response.StatusCode == http.StatusForbidden && response.Header.Get("X-RateLimit-Remaining") == "0"):
		return nil, &listError{code: ListErrorRateLimited, detail: fmt.Sprintf("%s returned HTTP %d (rate limited)", path, response.StatusCode)}
	default:
		return nil, &listError{code: ListErrorGitHub, detail: fmt.Sprintf("%s returned HTTP %d", path, response.StatusCode)}
	}
}

// Disabled reports whether sign-in is turned off for local development, in
// which case every request runs as the development user.
func (s *Service) Disabled() bool { return s.cfg.Disabled }

// stripURL keeps the transport error but drops the request URL net/http
// wraps around it, which for the token request carries nothing secret today
// but would the moment a parameter moved into the query string.
func stripURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
