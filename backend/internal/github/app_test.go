package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sbomdelta/internal/config"
)

// listingPage is what the fake GitHub returns for one page of
// GET /installation/repositories.
type listingPage struct {
	status int
	total  int
	ids    []int64
}

// fakeGitHub serves an installation token exchange and the given listing
// pages, linking each page to the next.
func fakeGitHub(t *testing.T, pages []listingPage) (*App, *int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	var server *httptest.Server
	listCalls := 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("token exchange was not signed with the app JWT")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"token":"ghs_test","expires_at":"2099-01-01T00:00:00Z"}`)

		case r.Method == http.MethodGet && r.URL.Path == "/installation/repositories":
			listCalls++
			if got := r.Header.Get("Authorization"); got != "token ghs_test" {
				t.Errorf("listing authorization = %q, want the installation token", got)
			}
			index := 0
			if p := r.URL.Query().Get("page"); p != "" {
				_, _ = fmt.Sscanf(p, "%d", &index)
				index--
			}
			page := pages[index]
			if page.status != 0 {
				w.WriteHeader(page.status)
				_, _ = fmt.Fprint(w, `{"message":"server error"}`)
				return
			}
			if index+1 < len(pages) {
				w.Header().Set("Link", fmt.Sprintf(`<%s/installation/repositories?per_page=100&page=%d>; rel="next"`,
					server.URL, index+2))
			}
			repos := make([]map[string]any, 0, len(page.ids))
			for _, id := range page.ids {
				repos = append(repos, map[string]any{"id": id, "name": fmt.Sprintf("r%d", id), "full_name": fmt.Sprintf("acme/r%d", id)})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": page.total, "repositories": repos})

		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	return NewApp(config.GitHub{AppID: 1, PrivateKey: keyPEM, APIBaseURL: server.URL + "/"}), &listCalls
}

// ListInstallationRepositories must authenticate as the installation and
// follow every page: one that stopped at page one would get every repository
// past the hundredth revoked.
func TestListInstallationRepositoriesFollowsPagination(t *testing.T) {
	app, calls := fakeGitHub(t, []listingPage{{total: 2, ids: []int64{1}}, {total: 2, ids: []int64{2}}})

	repos, err := app.ListInstallationRepositories(context.Background(), 77)
	if err != nil {
		t.Fatalf("ListInstallationRepositories() error = %v", err)
	}
	if len(repos) != 2 || repos[0].GetID() != 1 || repos[1].GetID() != 2 {
		t.Errorf("repos = %v, want 1 and 2 from both pages", repos)
	}
	if *calls != 2 {
		t.Errorf("listing requests = %d, want 2", *calls)
	}
}

// Any doubt about the listing must surface as an error: reconciliation turns
// a missing repository into a revocation, so a partial list is never safe.
func TestListInstallationRepositoriesRejectsUnreliableListings(t *testing.T) {
	tests := []struct {
		name  string
		pages []listingPage
	}{
		{"second page fails", []listingPage{{total: 2, ids: []int64{1}}, {status: http.StatusBadGateway}}},
		// A repository was removed between fetches, shifting page two: repo 2
		// would otherwise be skipped and revoked.
		{"total changes mid-listing", []listingPage{{total: 3, ids: []int64{1}}, {total: 2, ids: []int64{3}}}},
		{"fewer repositories than reported", []listingPage{{total: 3, ids: []int64{1}}, {total: 3, ids: []int64{2}}}},
		{"first page fails", []listingPage{{status: http.StatusInternalServerError}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _ := fakeGitHub(t, tt.pages)
			repos, err := app.ListInstallationRepositories(context.Background(), 77)
			if err == nil {
				t.Fatalf("ListInstallationRepositories() = %d repos, want an error", len(repos))
			}
			if repos != nil {
				t.Errorf("repos = %v, want nil alongside the error", repos)
			}
		})
	}
}
