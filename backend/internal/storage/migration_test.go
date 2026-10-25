package storage_test

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"

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
