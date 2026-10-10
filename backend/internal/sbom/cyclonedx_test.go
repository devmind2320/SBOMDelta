package sbom

import (
	"testing"
)

// syftLikeBOM mirrors the shape syft emits for a Node project: a flat
// component list, a dependency graph naming the direct dependencies, and a
// file-type entry with no PURL that must be ignored.
const syftLikeBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:8b1b4f9e-0000-4000-8000-000000000000",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {"type": "application", "name": "syft", "version": "1.18.1"}
      ]
    },
    "component": {"bom-ref": "root", "type": "file", "name": "/src"}
  },
  "components": [
    {
      "bom-ref": "ref-express",
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [{"license": {"id": "MIT"}}]
    },
    {
      "bom-ref": "ref-lodash",
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"expression": "MIT OR Apache-2.0"}]
    },
    {
      "bom-ref": "ref-qs",
      "type": "library",
      "name": "qs",
      "version": "6.11.0",
      "purl": "pkg:npm/qs@6.11.0"
    },
    {
      "bom-ref": "ref-scoped",
      "type": "library",
      "name": "utils",
      "group": "@acme",
      "version": "2.0.0",
      "purl": "pkg:npm/%40acme/utils@2.0.0",
      "licenses": [{"license": {"name": "Custom Commercial"}}]
    },
    {
      "bom-ref": "ref-readme",
      "type": "file",
      "name": "README.md"
    }
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["ref-express", "ref-scoped"]},
    {"ref": "ref-express", "dependsOn": ["ref-qs"]}
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	doc, err := ParseCycloneDX([]byte(syftLikeBOM))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}

	if doc.Tool != "syft 1.18.1" {
		t.Errorf("tool = %q, want %q", doc.Tool, "syft 1.18.1")
	}
	// The README entry has no PURL and must not become a component.
	if len(doc.Components) != 4 {
		t.Fatalf("components = %d, want 4; got %+v", len(doc.Components), doc.Components)
	}

	byName := make(map[string]Component, len(doc.Components))
	for _, component := range doc.Components {
		byName[component.Name] = component
	}

	express, ok := byName["express"]
	if !ok {
		t.Fatal("express is missing from the parsed components")
	}
	if express.Identity != "pkg:npm/express" {
		t.Errorf("express identity = %q, want %q", express.Identity, "pkg:npm/express")
	}
	if express.Version != "4.18.2" || express.Ecosystem != "npm" {
		t.Errorf("express = %s@%s in %q, want 4.18.2 in npm", express.Name, express.Version, express.Ecosystem)
	}
	if len(express.Licenses) != 1 || express.Licenses[0] != "MIT" {
		t.Errorf("express licenses = %v, want [MIT]", express.Licenses)
	}
	if !express.Direct {
		t.Error("express should be a direct dependency of the root component")
	}

	if qs := byName["qs"]; qs.Direct {
		t.Error("qs is only reachable through express and should be transitive")
	}

	// A license expression and a discrete license ID are different fields.
	if lodash := byName["lodash"]; lodash.LicenseExpression != "MIT OR Apache-2.0" {
		t.Errorf("lodash expression = %q, want %q", lodash.LicenseExpression, "MIT OR Apache-2.0")
	}

	scoped, ok := byName["@acme/utils"]
	if !ok {
		t.Fatalf("scoped package missing; parsed names = %v", keys(byName))
	}
	if scoped.Identity != "pkg:npm/%40acme/utils" {
		t.Errorf("scoped identity = %q, want the namespace preserved", scoped.Identity)
	}
	// A non-SPDX license name is still worth recording for the license matrix.
	if len(scoped.Licenses) != 1 || scoped.Licenses[0] != "Custom Commercial" {
		t.Errorf("scoped licenses = %v, want [Custom Commercial]", scoped.Licenses)
	}
}

// cdxgen nests transitive dependencies under their parent rather than emitting
// a flat list; both shapes have to produce the same component set.
func TestParseCycloneDXNestedComponents(t *testing.T) {
	const nested = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "version": 1,
	  "components": [
	    {
	      "type": "library", "name": "parent", "version": "1.0.0",
	      "purl": "pkg:npm/parent@1.0.0",
	      "components": [
	        {"type": "library", "name": "child", "version": "2.0.0", "purl": "pkg:npm/child@2.0.0"}
	      ]
	    }
	  ]
	}`

	doc, err := ParseCycloneDX([]byte(nested))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2 (parent and nested child)", len(doc.Components))
	}
}

func TestParseCycloneDXDeduplicatesPURLs(t *testing.T) {
	const duplicated = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "version": 1,
	  "components": [
	    {"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"},
	    {"type": "library", "name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"}
	  ]
	}`

	doc, err := ParseCycloneDX([]byte(duplicated))
	if err != nil {
		t.Fatalf("ParseCycloneDX() error = %v", err)
	}
	if len(doc.Components) != 1 {
		t.Errorf("components = %d, want 1; the PURL is the key within a scan", len(doc.Components))
	}
}

func TestParseCycloneDXRejectsGarbage(t *testing.T) {
	if _, err := ParseCycloneDX([]byte("not json")); err == nil {
		t.Error("ParseCycloneDX() error = nil, want a decode failure")
	}
}

func TestParseIdentity(t *testing.T) {
	tests := []struct {
		purl      string
		identity  string
		version   string
		ecosystem string
		name      string
	}{
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash", "4.17.21", "npm", "lodash"},
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.1", "pkg:golang/github.com/gin-gonic/gin", "v1.9.1", "golang", "github.com/gin-gonic/gin"},
		{"pkg:deb/debian/openssl@1.1.1n?arch=amd64", "pkg:deb/debian/openssl", "1.1.1n", "deb", "debian/openssl"},
		// Qualifiers must not leak into the identity, or an architecture change
		// would read as a different dependency.
		{"pkg:maven/org.apache/commons@1.0?type=jar", "pkg:maven/org.apache/commons", "1.0", "maven", "org.apache/commons"},
	}

	for _, tt := range tests {
		identity, version, ecosystem, name := ParseIdentity(tt.purl)
		if identity != tt.identity || version != tt.version || ecosystem != tt.ecosystem || name != tt.name {
			t.Errorf("ParseIdentity(%q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				tt.purl, identity, version, ecosystem, name,
				tt.identity, tt.version, tt.ecosystem, tt.name)
		}
	}
}

func keys(m map[string]Component) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
