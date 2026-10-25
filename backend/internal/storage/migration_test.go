package storage_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"sbomdelta/internal/models"
	"sbomdelta/internal/storage"
	"sbomdelta/migrations"
)

// TestMigration0004UpgradesExistingDatabase starts from a database at
// 0003 -- the schema production runs before this change -- with real history
// in it, then runs Migrate. Every row must survive, and every existing
// repository must come out active, exactly as it was presented before.
func TestMigration0004UpgradesExistingDatabase(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()
	const schema = "test_migration_0004"

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()
	pool := db.Pool()

	// Bring the schema to 0003 exactly as the runner would have.
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, version := range []string{
		"0001_init.up.sql", "0002_enrichment_state.up.sql", "0003_manual_repositories.up.sql",
	} {
		sql, err := migrations.FS.ReadFile(version)
		if err != nil {
			t.Fatalf("read %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			t.Fatalf("record %s: %v", version, err)
		}
	}

	// History written by the pre-0004 code, in raw SQL so it cannot depend on
	// columns that do not exist yet.
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (id, github_installation_id, account_login) VALUES (1, 4242, 'devmind2320');
		INSERT INTO repositories (id, installation_id, github_repo_id, owner, name) VALUES
			(1, 1, 1001, 'devmind2320', 'api'),
			(2, 1, 1002, 'devmind2320', 'web');
		INSERT INTO repositories (id, owner, name, clone_url) VALUES
			(3, 'sigstore', 'cosign', 'https://github.com/sigstore/cosign.git');
		INSERT INTO scans (id, repository_id, commit_sha, trigger, status, component_count) VALUES
			(1, 1, 'aaaa', 'push', 'completed', 1),
			(2, 1, 'bbbb', 'push', 'completed', 1),
			(3, 3, 'cccc', 'manual', 'completed', 1);
		INSERT INTO components (scan_id, purl, name, version, ecosystem) VALUES
			(1, 'pkg:npm/a@1', 'a', '1', 'npm'),
			(2, 'pkg:npm/a@2', 'a', '2', 'npm'),
			(3, 'pkg:golang/b@1', 'b', '1', 'golang');
		INSERT INTO drift_events (scan_id, base_scan_id, change_type, identity, purl, name, ecosystem, old_version, new_version)
			VALUES (2, 1, 'updated', 'pkg:npm/a', 'pkg:npm/a@2', 'a', 'npm', '1', '2');`); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	counts := func() map[string]int {
		out := map[string]int{}
		for _, table := range []string{"installations", "repositories", "scans", "components", "drift_events"} {
			var n int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			out[table] = n
		}
		return out
	}
	before := counts()

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	var applied bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '0004_repository_access.up.sql')`).
		Scan(&applied); err != nil || !applied {
		t.Fatalf("0004 applied = %v (err %v), want true", applied, err)
	}

	after := counts()
	for table, n := range before {
		if after[table] != n {
			t.Errorf("%s rows = %d after migrating, want %d", table, after[table], n)
		}
	}

	repos, err := db.ListRepositories(ctx, storage.AccessFilterActive)
	if err != nil {
		t.Fatalf("ListRepositories() error = %v", err)
	}
	if len(repos) != 3 {
		t.Errorf("active repositories = %d, want all 3 pre-existing rows active", len(repos))
	}
	for _, repo := range repos {
		if repo.Access != models.AccessActive || repo.AccessRevokedAt != nil {
			t.Errorf("%s access = %q (revokedAt %v), want active", repo.FullName(), repo.Access, repo.AccessRevokedAt)
		}
	}

	// The down migration only drops the new column; history is untouched.
	down, err := migrations.FS.ReadFile("0004_repository_access.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	afterDown := counts()
	for table, n := range before {
		if afterDown[table] != n {
			t.Errorf("%s rows = %d after rolling back, want %d", table, afterDown[table], n)
		}
	}
}

// TestMigration0005AddsInitialTrigger upgrades a database at 0004 with scan
// history. Existing scans must be untouched, the new trigger must be usable
// straight after Migrate, and the down migration must keep every scan,
// relabelling initial ones as manual.
func TestMigration0005AddsInitialTrigger(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()
	const schema = "test_migration_0005"

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()
	pool := db.Pool()

	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, version := range []string{
		"0001_init.up.sql", "0002_enrichment_state.up.sql", "0003_manual_repositories.up.sql",
		"0004_repository_access.up.sql",
	} {
		sql, err := migrations.FS.ReadFile(version)
		if err != nil {
			t.Fatalf("read %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", version, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			t.Fatalf("record %s: %v", version, err)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO installations (id, github_installation_id, account_login) VALUES (1, 4242, 'devmind2320');
		INSERT INTO repositories (id, installation_id, github_repo_id, owner, name) VALUES
			(1, 1, 1001, 'devmind2320', 'api'),
			(2, 1, 1002, 'devmind2320', 'web');
		INSERT INTO scans (id, repository_id, commit_sha, trigger, status, component_count) VALUES
			(1, 1, 'aaaa', 'push', 'completed', 1),
			(2, 1, 'bbbb', 'manual', 'completed', 1);
		SELECT setval('scans_id_seq', 2);`); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scans (repository_id, commit_sha, trigger) VALUES (2, 'cccc', 'initial')`); err == nil {
		t.Fatal("inserting an initial scan before 0005 succeeded; the test is not starting from 0004")
	}

	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// IF NOT EXISTS makes a re-run of the file harmless, e.g. after a crash
	// between applying it and recording it.
	up, err := migrations.FS.ReadFile("0005_initial_scan_trigger.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(up)); err != nil {
		t.Fatalf("re-applying 0005: %v", err)
	}

	scan, created, err := db.CreateInitialScan(ctx, 2, "cccc")
	if err != nil || !created || scan.Trigger != models.TriggerInitial {
		t.Fatalf("CreateInitialScan() = %+v, %v, %v; want a new initial scan", scan, created, err)
	}
	triggers := func() map[int64]string {
		out := map[int64]string{}
		rows, err := pool.Query(ctx, `SELECT id, trigger::text FROM scans ORDER BY id`)
		if err != nil {
			t.Fatalf("list scans: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var trigger string
			if err := rows.Scan(&id, &trigger); err != nil {
				t.Fatalf("scan row: %v", err)
			}
			out[id] = trigger
		}
		return out
	}
	want := map[int64]string{1: "push", 2: "manual", scan.ID: "initial"}
	if got := triggers(); len(got) != 3 || got[1] != want[1] || got[2] != want[2] || got[scan.ID] != want[scan.ID] {
		t.Errorf("triggers after migrating = %v, want %v", got, want)
	}

	down, err := migrations.FS.ReadFile("0005_initial_scan_trigger.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	want[scan.ID] = "manual"
	if got := triggers(); len(got) != 3 || got[1] != want[1] || got[2] != want[2] || got[scan.ID] != want[scan.ID] {
		t.Errorf("triggers after rolling back = %v, want %v", got, want)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scans (repository_id, commit_sha, trigger) VALUES (2, 'dddd', 'initial')`); err == nil {
		t.Error("initial trigger still accepted after rolling back 0005")
	}
}

// A database built from nothing ends up with every trigger the code writes,
// in declaration order.
func TestCleanDatabaseHasEveryScanTrigger(t *testing.T) {
	db := newTestDB(t)
	var values string
	if err := db.Pool().QueryRow(context.Background(),
		`SELECT array_to_string(enum_range(NULL::scan_trigger), ',')`).Scan(&values); err != nil {
		t.Fatalf("read scan_trigger: %v", err)
	}
	want := strings.Join([]string{
		string(models.TriggerPush), string(models.TriggerPullRequest), string(models.TriggerManual),
		string(models.TriggerBackfill), string(models.TriggerInitial),
	}, ",")
	if values != want {
		t.Errorf("scan_trigger = %s, want %s", values, want)
	}
}

// TestMigration0006UsersAndSessions checks the sign-in tables on a fresh
// database, their cascade, and that the down migration removes only them.
func TestMigration0006UsersAndSessions(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()
	const schema = "test_migration_0006"

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()
	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	pool := db.Pool()

	user, err := db.UpsertUser(ctx, models.User{GitHubUserID: 4001, Login: "devmind2320"})
	if err != nil {
		t.Fatalf("UpsertUser() error = %v", err)
	}
	if err := db.CreateSession(ctx, []byte("hash-1"), user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := db.CreateSession(ctx, []byte("hash-1"), user.ID, time.Now().Add(time.Hour)); err == nil {
		t.Error("two sessions were stored under one token hash")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var sessions int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Errorf("sessions after deleting their user = %d (err %v), want 0", sessions, err)
	}

	// Roll back in reverse order, as a real rollback would: 0007's tables
	// refer to users.
	for _, file := range []string{"0007_user_repositories.down.sql", "0006_users_sessions.down.sql"} {
		down, err := migrations.FS.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if _, err := pool.Exec(ctx, string(down)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = $1 AND table_name IN ('users', 'sessions')`, schema).Scan(&remaining); err != nil || remaining != 0 {
		t.Errorf("sign-in tables after rolling back = %d (err %v), want 0", remaining, err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM repositories LIMIT 1`); err != nil {
		t.Errorf("rolling back 0006 touched other tables: %v", err)
	}
}

// Migration 0007 adds the per-user repository list and tracked list: rows go
// with their user (and a tracked row with its repository), and rolling it back
// removes exactly what it added.
func TestMigration0007UserRepositories(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping database integration tests")
	}
	ctx := context.Background()
	const schema = "test_migration_0007"

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := storage.Open(ctx, parsed.String())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()
	if err := db.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	pool := db.Pool()

	installation, err := db.UpsertInstallation(ctx, models.Installation{GitHubInstallationID: 4242, AccountLogin: "acme", AccountType: "Organization"})
	if err != nil {
		t.Fatal(err)
	}
	githubID := int64(99001)
	repo, err := db.UpsertRepository(ctx, models.Repository{InstallationID: &installation.ID, GitHubRepoID: &githubID, Owner: "acme", Name: "api", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.UpsertUser(ctx, models.User{GitHubUserID: 4001, Login: "devmind2320"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReplaceUserRepositories(ctx, user.ID, []models.AccessibleRepository{
		{GitHubRepoID: githubID, GitHubInstallationID: 4242, Owner: "acme", Name: "api", Private: true},
	}, time.Now()); err != nil {
		t.Fatalf("ReplaceUserRepositories() error = %v", err)
	}
	if err := db.TrackRepository(ctx, user.ID, repo.ID); err != nil {
		t.Fatalf("TrackRepository() error = %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_repositories (user_id, github_repo_id, github_installation_id, owner, name, private, listed_at)
		VALUES ($1, $2, 4242, 'acme', 'api', true, now())`, user.ID, githubID); err == nil {
		t.Error("one repository was listed twice for the same user")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM repositories WHERE id = $1`, repo.ID); err != nil {
		t.Fatalf("delete repository: %v", err)
	}
	var tracked, listed int
	if err := pool.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM user_tracked_repositories), (SELECT COUNT(*) FROM user_repositories)`).
		Scan(&tracked, &listed); err != nil || tracked != 0 || listed != 1 {
		t.Errorf("after deleting the repository: tracked %d listed %d (err %v), want 0 and the GitHub listing kept", tracked, listed, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_repositories`).Scan(&listed); err != nil || listed != 0 {
		t.Errorf("listed after deleting the user = %d (err %v), want 0", listed, err)
	}

	down, err := migrations.FS.ReadFile("0007_user_repositories.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("apply down migration: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM information_schema.tables
		        WHERE table_schema = $1 AND table_name IN ('user_repositories', 'user_tracked_repositories'))
		     + (SELECT COUNT(*) FROM information_schema.columns
		        WHERE table_schema = $1 AND table_name = 'users' AND column_name LIKE 'repos_list%')`, schema).
		Scan(&remaining); err != nil || remaining != 0 {
		t.Errorf("0007 objects after rolling back = %d (err %v), want 0", remaining, err)
	}
	if _, err := pool.Exec(ctx, `SELECT id, login FROM users LIMIT 1`); err != nil {
		t.Errorf("rolling back 0007 broke the users table: %v", err)
	}
}

// Sessions are found only by hash and only while unexpired; signing in sweeps
// expired ones; a returning user's login and avatar are refreshed.
func TestUserAndSessionStorage(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	user, err := db.UpsertUser(ctx, models.User{GitHubUserID: 4001, Login: "OldName", AvatarURL: "https://a/1"})
	if err != nil {
		t.Fatalf("UpsertUser() error = %v", err)
	}
	renamed, err := db.UpsertUser(ctx, models.User{GitHubUserID: 4001, Login: "devmind2320"})
	if err != nil {
		t.Fatalf("UpsertUser() again error = %v", err)
	}
	if renamed.ID != user.ID || renamed.Login != "devmind2320" || renamed.AvatarURL != "" {
		t.Errorf("returning user = %+v, want the same row with the new login", renamed)
	}

	if err := db.CreateSession(ctx, []byte("old"), user.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("CreateSession(expired) error = %v", err)
	}
	if _, err := db.SessionUser(ctx, []byte("old")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expired session lookup error = %v, want ErrNotFound", err)
	}
	if err := db.CreateSession(ctx, []byte("live"), user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	var stored int
	if err := db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&stored); err != nil || stored != 1 {
		t.Errorf("sessions after a new sign-in = %d (err %v), want the expired one swept", stored, err)
	}
	got, err := db.SessionUser(ctx, []byte("live"))
	if err != nil || got.ID != user.ID {
		t.Fatalf("SessionUser() = %+v, %v", got, err)
	}
	if _, err := db.SessionUser(ctx, []byte("unknown")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown session error = %v, want ErrNotFound", err)
	}
	if err := db.DeleteSession(ctx, []byte("live")); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	if err := db.DeleteSession(ctx, []byte("live")); err != nil {
		t.Errorf("deleting a deleted session error = %v, want nil", err)
	}
	if _, err := db.SessionUser(ctx, []byte("live")); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("deleted session error = %v, want ErrNotFound", err)
	}
}
