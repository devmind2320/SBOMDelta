// Package diff compares two normalized SBOMs and reports what changed.
//
// This is the core of SBOMDelta: every other subsystem exists to feed this one
// or to act on its output. The comparison is done on dependency *identity*
// (the version-less PURL) rather than on the full PURL, which is what lets a
// version bump register as an update instead of an unrelated add plus remove.
package diff

import (
	"sort"

	"github.com/Masterminds/semver/v3"

	"sbomdelta/internal/sbom"
)

// ChangeType classifies what happened to one dependency between two scans.
type ChangeType string

const (
	Added     ChangeType = "added"
	Removed   ChangeType = "removed"
	Updated   ChangeType = "updated"
	Unchanged ChangeType = "unchanged"
)

// Direction describes which way a version moved. Not every ecosystem uses
// semver, so DirectionUnknown is a normal outcome rather than an error.
type Direction string

const (
	DirectionUpgrade   Direction = "upgrade"
	DirectionDowngrade Direction = "downgrade"
	DirectionUnknown   Direction = "unknown"
	DirectionNone      Direction = ""
)

// Change is a single entry in a diff.
type Change struct {
	Type      ChangeType `json:"type"`
	Identity  string     `json:"identity"`
	Name      string     `json:"name"`
	Ecosystem string     `json:"ecosystem"`
	// PURL identifies the component this change is about: the new state for
	// added/updated/unchanged, the old state for removed.
	PURL       string    `json:"purl"`
	OldVersion string    `json:"oldVersion,omitempty"`
	NewVersion string    `json:"newVersion,omitempty"`
	Direction  Direction `json:"direction,omitempty"`
	// Direct reports whether this is a declared dependency rather than a
	// transitive one, taken from whichever side of the diff still has it.
	Direct bool `json:"direct"`

	Old *sbom.Component `json:"-"`
	New *sbom.Component `json:"-"`
}

// Result is the full comparison of a base SBOM against a head SBOM.
type Result struct {
	Added     []Change `json:"added"`
	Removed   []Change `json:"removed"`
	Updated   []Change `json:"updated"`
	Unchanged []Change `json:"unchanged"`
}

// Changes returns added, removed and updated entries -- everything except the
// unchanged baseline -- in a stable order.
func (r *Result) Changes() []Change {
	out := make([]Change, 0, len(r.Added)+len(r.Removed)+len(r.Updated))
	out = append(out, r.Added...)
	out = append(out, r.Updated...)
	out = append(out, r.Removed...)
	return out
}

// HasDrift reports whether the dependency set moved at all.
func (r *Result) HasDrift() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Updated) > 0
}

// Compare diffs a base SBOM against a head SBOM.
//
// A nil base means there is no previous scan to compare against -- the first
// scan of a repository. Every component is then reported as unchanged rather
// than as added, so that a repository's initial baseline does not read as one
// enormous drift event.
func Compare(base, head []sbom.Component) *Result {
	result := &Result{}

	if base == nil {
		for i := range head {
			component := head[i]
			result.Unchanged = append(result.Unchanged, Change{
				Type:       Unchanged,
				Identity:   component.Identity,
				Name:       component.Name,
				Ecosystem:  component.Ecosystem,
				PURL:       component.PURL,
				OldVersion: component.Version,
				NewVersion: component.Version,
				Direct:     component.Direct,
				New:        &head[i],
			})
		}
		sortChanges(result.Unchanged)
		return result
	}

	oldByIdentity := groupByIdentity(base)
	newByIdentity := groupByIdentity(head)

	for _, identity := range identityUnion(oldByIdentity, newByIdentity) {
		olds := oldByIdentity[identity]
		news := newByIdentity[identity]

		retained, droppedOld, addedNew := partitionByVersion(olds, news)

		for _, component := range retained {
			result.Unchanged = append(result.Unchanged, Change{
				Type:       Unchanged,
				Identity:   identity,
				Name:       component.Name,
				Ecosystem:  component.Ecosystem,
				PURL:       component.PURL,
				OldVersion: component.Version,
				NewVersion: component.Version,
				Direct:     component.Direct,
				New:        component,
			})
		}

		// Versions that vanished paired against versions that appeared are
		// version changes. Most identities have exactly one of each; packages
		// that legitimately ship several versions side by side (common in npm
		// trees) are paired in version order, which keeps a 2.x -> 2.y bump
		// from being reported against an unrelated 1.x line.
		sortComponentsByVersion(droppedOld)
		sortComponentsByVersion(addedNew)

		paired := min(len(droppedOld), len(addedNew))
		for i := 0; i < paired; i++ {
			previous, current := droppedOld[i], addedNew[i]
			result.Updated = append(result.Updated, Change{
				Type:       Updated,
				Identity:   identity,
				Name:       current.Name,
				Ecosystem:  current.Ecosystem,
				PURL:       current.PURL,
				OldVersion: previous.Version,
				NewVersion: current.Version,
				Direction:  compareVersions(previous.Version, current.Version),
				Direct:     current.Direct || previous.Direct,
				Old:        previous,
				New:        current,
			})
		}

		for _, component := range addedNew[paired:] {
			result.Added = append(result.Added, Change{
				Type:       Added,
				Identity:   identity,
				Name:       component.Name,
				Ecosystem:  component.Ecosystem,
				PURL:       component.PURL,
				NewVersion: component.Version,
				Direct:     component.Direct,
				New:        component,
			})
		}

		for _, component := range droppedOld[paired:] {
			result.Removed = append(result.Removed, Change{
				Type:       Removed,
				Identity:   identity,
				Name:       component.Name,
				Ecosystem:  component.Ecosystem,
				PURL:       component.PURL,
				OldVersion: component.Version,
				Direct:     component.Direct,
				Old:        component,
			})
		}
	}

	sortChanges(result.Added)
	sortChanges(result.Removed)
	sortChanges(result.Updated)
	sortChanges(result.Unchanged)
	return result
}

// partitionByVersion splits two version sets of the same dependency into the
// versions present in both, only in the base, and only in the head.
func partitionByVersion(olds, news []*sbom.Component) (retained, droppedOld, addedNew []*sbom.Component) {
	newVersions := make(map[string]*sbom.Component, len(news))
	for _, component := range news {
		newVersions[component.Version] = component
	}
	oldVersions := make(map[string]struct{}, len(olds))
	for _, component := range olds {
		oldVersions[component.Version] = struct{}{}
	}

	for _, component := range olds {
		if current, ok := newVersions[component.Version]; ok {
			retained = append(retained, current)
			continue
		}
		droppedOld = append(droppedOld, component)
	}
	for _, component := range news {
		if _, ok := oldVersions[component.Version]; !ok {
			addedNew = append(addedNew, component)
		}
	}
	return retained, droppedOld, addedNew
}

func groupByIdentity(components []sbom.Component) map[string][]*sbom.Component {
	grouped := make(map[string][]*sbom.Component, len(components))
	for i := range components {
		identity := components[i].Identity
		grouped[identity] = append(grouped[identity], &components[i])
	}
	return grouped
}

func identityUnion(a, b map[string][]*sbom.Component) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	union := make([]string, 0, len(a)+len(b))
	for _, set := range []map[string][]*sbom.Component{a, b} {
		for identity := range set {
			if _, dup := seen[identity]; dup {
				continue
			}
			seen[identity] = struct{}{}
			union = append(union, identity)
		}
	}
	sort.Strings(union)
	return union
}

// compareVersions reports which way a version moved, falling back to
// DirectionUnknown for the many ecosystems that do not use semver (Debian
// epochs, Maven qualifiers, Go pseudo-versions with odd prefixes).
func compareVersions(previous, current string) Direction {
	oldVersion, oldErr := semver.NewVersion(previous)
	newVersion, newErr := semver.NewVersion(current)
	if oldErr != nil || newErr != nil {
		return DirectionUnknown
	}
	switch newVersion.Compare(oldVersion) {
	case 1:
		return DirectionUpgrade
	case -1:
		return DirectionDowngrade
	default:
		// Equal under semver but textually different, e.g. 1.0 vs 1.0.0.
		return DirectionNone
	}
}

func sortComponentsByVersion(components []*sbom.Component) {
	sort.SliceStable(components, func(i, j int) bool {
		a, aErr := semver.NewVersion(components[i].Version)
		b, bErr := semver.NewVersion(components[j].Version)
		if aErr == nil && bErr == nil {
			return a.LessThan(b)
		}
		return components[i].Version < components[j].Version
	})
}

func sortChanges(changes []Change) {
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Identity != changes[j].Identity {
			return changes[i].Identity < changes[j].Identity
		}
		return changes[i].NewVersion < changes[j].NewVersion
	})
}
