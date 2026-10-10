package diff

import (
	"testing"

	"sbomdelta/internal/sbom"
)

// component builds a normalized component the way the CycloneDX parser would,
// so tests exercise the same identity derivation as production.
func component(purl string) sbom.Component {
	identity, version, ecosystem, name := sbom.ParseIdentity(purl)
	return sbom.Component{
		PURL:      purl,
		Identity:  identity,
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
	}
}

func components(purls ...string) []sbom.Component {
	out := make([]sbom.Component, 0, len(purls))
	for _, purl := range purls {
		out = append(out, component(purl))
	}
	return out
}

func TestCompareAddedRemovedUpdated(t *testing.T) {
	base := components(
		"pkg:npm/axios@1.6.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/left-pad@1.3.0",
	)
	head := components(
		"pkg:npm/axios@1.7.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/express@4.18.2",
	)

	result := Compare(base, head)

	if len(result.Added) != 1 || result.Added[0].PURL != "pkg:npm/express@4.18.2" {
		t.Fatalf("added = %+v, want only express@4.18.2", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].PURL != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("removed = %+v, want only left-pad@1.3.0", result.Removed)
	}
	if len(result.Updated) != 1 {
		t.Fatalf("updated = %+v, want one entry", result.Updated)
	}
	if len(result.Unchanged) != 1 || result.Unchanged[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unchanged = %+v, want only lodash@4.17.21", result.Unchanged)
	}

	update := result.Updated[0]
	if update.Name != "axios" || update.OldVersion != "1.6.0" || update.NewVersion != "1.7.0" {
		t.Errorf("update = %+v, want axios 1.6.0 -> 1.7.0", update)
	}
	if update.Direction != DirectionUpgrade {
		t.Errorf("direction = %q, want %q", update.Direction, DirectionUpgrade)
	}
	if !result.HasDrift() {
		t.Error("HasDrift() = false, want true")
	}
}

// A version bump must not surface as an unrelated add plus remove -- that is
// the distinction the whole product rests on.
func TestCompareVersionBumpIsNotAddPlusRemove(t *testing.T) {
	result := Compare(
		components("pkg:npm/lodash@4.17.21"),
		components("pkg:npm/lodash@4.18.0"),
	)

	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("added=%d removed=%d, want 0 and 0", len(result.Added), len(result.Removed))
	}
	if len(result.Updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(result.Updated))
	}
}

func TestCompareDowngrade(t *testing.T) {
	result := Compare(
		components("pkg:npm/axios@1.7.0"),
		components("pkg:npm/axios@1.6.0"),
	)

	if len(result.Updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(result.Updated))
	}
	if got := result.Updated[0].Direction; got != DirectionDowngrade {
		t.Errorf("direction = %q, want %q", got, DirectionDowngrade)
	}
}

// Debian-style versions are not semver; the change is still reported, only the
// direction is unknown.
func TestCompareNonSemverDirectionUnknown(t *testing.T) {
	result := Compare(
		components("pkg:deb/debian/openssl@1.1.1n-0+deb11u3"),
		components("pkg:deb/debian/openssl@1.1.1w-0+deb11u1"),
	)

	if len(result.Updated) != 1 {
		t.Fatalf("updated = %d, want 1", len(result.Updated))
	}
	if got := result.Updated[0].Direction; got != DirectionUnknown {
		t.Errorf("direction = %q, want %q", got, DirectionUnknown)
	}
}

// npm trees routinely carry several versions of one package at once. The
// unchanged copy must stay unchanged while the other line moves.
func TestCompareMultipleVersionsOfSameIdentity(t *testing.T) {
	base := components("pkg:npm/lodash@3.10.1", "pkg:npm/lodash@4.17.21")
	head := components("pkg:npm/lodash@3.10.1", "pkg:npm/lodash@4.17.22")

	result := Compare(base, head)

	if len(result.Unchanged) != 1 || result.Unchanged[0].NewVersion != "3.10.1" {
		t.Fatalf("unchanged = %+v, want lodash 3.10.1", result.Unchanged)
	}
	if len(result.Updated) != 1 {
		t.Fatalf("updated = %+v, want one entry", result.Updated)
	}
	if update := result.Updated[0]; update.OldVersion != "4.17.21" || update.NewVersion != "4.17.22" {
		t.Errorf("update = %s -> %s, want 4.17.21 -> 4.17.22", update.OldVersion, update.NewVersion)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Errorf("added=%d removed=%d, want 0 and 0", len(result.Added), len(result.Removed))
	}
}

// Dropping one of two co-installed versions is a removal, not a downgrade.
func TestCompareDroppedDuplicateVersion(t *testing.T) {
	base := components("pkg:npm/lodash@3.10.1", "pkg:npm/lodash@4.17.21")
	head := components("pkg:npm/lodash@4.17.21")

	result := Compare(base, head)

	if len(result.Removed) != 1 || result.Removed[0].OldVersion != "3.10.1" {
		t.Fatalf("removed = %+v, want lodash 3.10.1", result.Removed)
	}
	if len(result.Updated) != 0 {
		t.Errorf("updated = %+v, want none", result.Updated)
	}
}

// Namespaced PURLs must not collide with same-named packages elsewhere.
func TestCompareNamespacedIdentity(t *testing.T) {
	base := components("pkg:npm/%40scope/utils@1.0.0")
	head := components("pkg:npm/%40scope/utils@1.1.0", "pkg:npm/utils@2.0.0")

	result := Compare(base, head)

	if len(result.Updated) != 1 || result.Updated[0].Name != "@scope/utils" {
		t.Fatalf("updated = %+v, want @scope/utils", result.Updated)
	}
	if len(result.Added) != 1 || result.Added[0].Name != "utils" {
		t.Fatalf("added = %+v, want unscoped utils", result.Added)
	}
}

// The same name in two ecosystems is two dependencies.
func TestCompareEcosystemsAreDistinct(t *testing.T) {
	result := Compare(
		components("pkg:npm/requests@1.0.0"),
		components("pkg:pypi/requests@1.0.0"),
	)

	if len(result.Added) != 1 || result.Added[0].Ecosystem != "pypi" {
		t.Fatalf("added = %+v, want the pypi component", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].Ecosystem != "npm" {
		t.Fatalf("removed = %+v, want the npm component", result.Removed)
	}
}

// The first scan of a repository establishes the baseline; it is not a diff in
// which every dependency was just introduced.
func TestCompareNilBaseIsBaseline(t *testing.T) {
	result := Compare(nil, components("pkg:npm/axios@1.6.0", "pkg:npm/lodash@4.17.21"))

	if len(result.Added) != 0 {
		t.Errorf("added = %+v, want none for a baseline scan", result.Added)
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("unchanged = %d, want 2", len(result.Unchanged))
	}
	if result.HasDrift() {
		t.Error("HasDrift() = true, want false for a baseline scan")
	}
}

// An empty (non-nil) base is a real repository that had no dependencies, so
// everything in head genuinely is new.
func TestCompareEmptyBaseIsAllAdded(t *testing.T) {
	result := Compare([]sbom.Component{}, components("pkg:npm/axios@1.6.0"))

	if len(result.Added) != 1 {
		t.Fatalf("added = %d, want 1", len(result.Added))
	}
}

func TestCompareIdenticalSBOMsHaveNoDrift(t *testing.T) {
	set := components("pkg:npm/axios@1.6.0", "pkg:golang/github.com/gin-gonic/gin@1.9.1")

	result := Compare(set, set)

	if result.HasDrift() {
		t.Errorf("HasDrift() = true, want false; changes = %+v", result.Changes())
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("unchanged = %d, want 2", len(result.Unchanged))
	}
}

// Ordering must be stable so that stored drift rows and PR comments do not
// churn between runs of the same scan.
func TestCompareOutputIsDeterministic(t *testing.T) {
	base := components("pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0")
	head := components("pkg:npm/d@1.0.0", "pkg:npm/c@1.0.0")

	first := Compare(base, head)
	second := Compare(base, head)

	if len(first.Added) != len(second.Added) {
		t.Fatalf("added lengths differ: %d vs %d", len(first.Added), len(second.Added))
	}
	for i := range first.Added {
		if first.Added[i].PURL != second.Added[i].PURL {
			t.Fatalf("order differs at %d: %q vs %q", i, first.Added[i].PURL, second.Added[i].PURL)
		}
	}
	if first.Added[0].Name != "c" {
		t.Errorf("first added = %q, want %q (sorted by identity)", first.Added[0].Name, "c")
	}
}

// A component with no parseable PURL still has to be tracked rather than
// silently dropped from the comparison.
func TestCompareMalformedPURL(t *testing.T) {
	result := Compare(
		components("not-a-purl"),
		components("not-a-purl", "pkg:npm/axios@1.6.0"),
	)

	if len(result.Unchanged) != 1 || result.Unchanged[0].PURL != "not-a-purl" {
		t.Fatalf("unchanged = %+v, want the malformed entry preserved", result.Unchanged)
	}
	if len(result.Added) != 1 {
		t.Fatalf("added = %d, want 1", len(result.Added))
	}
}
