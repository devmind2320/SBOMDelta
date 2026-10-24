package sbom

import "testing"

func TestIsCommitSHA(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"0123456789ABCDEF0123456789ABCDEF01234567", true}, // case-insensitive
		{"0123456", false}, // short sha is not enough
		{"", false},
		{"main", false},
		{"0123456789abcdef0123456789abcdef0123456g", false}, // non-hex
	}
	for _, tt := range tests {
		if got := IsCommitSHA(tt.value); got != tt.want {
			t.Errorf("IsCommitSHA(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

// The version gate exists because a stale git silently breaks partial clone.
func TestParseGitVersion(t *testing.T) {
	tests := []struct {
		version string
		major   int
		minor   int
		ok      bool
	}{
		{"git version 2.50.1 (Apple Git-155)", 2, 50, true},
		{"git version 2.15.0", 2, 15, true},
		{"git version 2.19.0", 2, 19, true},
		{"not a version", 0, 0, false},
	}
	for _, tt := range tests {
		major, minor, ok := parseGitVersion(tt.version)
		if ok != tt.ok || major != tt.major || minor != tt.minor {
			t.Errorf("parseGitVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tt.version, major, minor, ok, tt.major, tt.minor, tt.ok)
		}
	}
}

// Guards the boundary the error message quotes: 2.19 introduced
// --filter=blob:none, so 2.18 and below must be rejected.
func TestGitVersionGateBoundary(t *testing.T) {
	tooOld := []string{"git version 1.9.5", "git version 2.18.0", "git version 2.15.0"}
	fresh := []string{"git version 2.19.0", "git version 2.39.3", "git version 3.0.0"}

	for _, version := range tooOld {
		major, minor, ok := parseGitVersion(version)
		if !ok {
			t.Fatalf("parseGitVersion(%q) failed", version)
		}
		if !(major < 2 || (major == 2 && minor < 19)) {
			t.Errorf("%q should be rejected as too old", version)
		}
	}
	for _, version := range fresh {
		major, minor, ok := parseGitVersion(version)
		if !ok {
			t.Fatalf("parseGitVersion(%q) failed", version)
		}
		if major < 2 || (major == 2 && minor < 19) {
			t.Errorf("%q should be accepted", version)
		}
	}
}
