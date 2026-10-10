// Package sbom generates and normalizes CycloneDX software bills of materials.
//
// Everything downstream of this package works on the normalized Component type
// rather than raw CycloneDX, so that swapping the generator (syft, cdxgen, a
// vendor-supplied SBOM uploaded by the user) does not ripple outward.
package sbom

import (
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
)

// Component is one entry in a bill of materials, identified by its Package URL.
type Component struct {
	// PURL is the full package URL including version, e.g.
	// pkg:npm/lodash@4.17.21. It is the primary key within a scan.
	PURL string `json:"purl"`
	// Identity is the PURL with version, qualifiers and subpath stripped, e.g.
	// pkg:npm/lodash. Two components share an identity when they are the same
	// dependency at different versions -- this is what the diff matches on.
	Identity  string   `json:"identity"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Type      string   `json:"type"`
	Licenses  []string `json:"licenses,omitempty"`
	// LicenseExpression is the SPDX expression when the SBOM carries one
	// (e.g. "MIT OR Apache-2.0"); Licenses holds discrete IDs.
	LicenseExpression string `json:"licenseExpression,omitempty"`
	// Direct reports whether the component is a declared dependency of the
	// root component rather than a transitive one.
	Direct bool `json:"direct"`
}

// Document is a normalized SBOM: the components of a single commit.
type Document struct {
	// Raw is the CycloneDX JSON exactly as produced by the generator. It is
	// what gets archived to blob storage -- we never re-serialize, so the
	// stored artifact stays byte-identical to the tool's output.
	Raw         []byte      `json:"-"`
	SpecVersion string      `json:"specVersion"`
	Tool        string      `json:"tool"`
	Components  []Component `json:"components"`
}

// ParseIdentity splits a PURL into its version-less identity and its version.
// Malformed PURLs are passed through unchanged rather than dropped: an SBOM
// entry we cannot parse is still an entry whose appearance or disappearance is
// worth reporting.
func ParseIdentity(purl string) (identity, version, ecosystem, name string) {
	instance, err := packageurl.FromString(purl)
	if err != nil {
		return purl, "", "", purl
	}

	name = instance.Name
	if instance.Namespace != "" {
		name = instance.Namespace + "/" + instance.Name
	}

	bare := packageurl.PackageURL{
		Type:      instance.Type,
		Namespace: instance.Namespace,
		Name:      instance.Name,
	}
	return bare.ToString(), instance.Version, instance.Type, name
}

// SortComponents orders components deterministically so that stored SBOM
// projections and diff output are stable across runs.
func SortComponents(components []Component) {
	sort.Slice(components, func(i, j int) bool {
		if components[i].Identity != components[j].Identity {
			return components[i].Identity < components[j].Identity
		}
		return components[i].Version < components[j].Version
	})
}

// normalizeLicenses de-duplicates and trims license identifiers.
func normalizeLicenses(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, license := range in {
		license = strings.TrimSpace(license)
		if license == "" {
			continue
		}
		if _, dup := seen[license]; dup {
			continue
		}
		seen[license] = struct{}{}
		out = append(out, license)
	}
	sort.Strings(out)
	return out
}
