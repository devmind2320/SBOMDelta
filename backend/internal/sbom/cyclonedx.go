package sbom

import (
	"bytes"
	"fmt"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// ParseCycloneDX normalizes a CycloneDX JSON document. Components without a
// PURL (the root component, file-type entries syft emits for loose files) are
// skipped: without a PURL there is no stable identity to diff on.
func ParseCycloneDX(raw []byte) (*Document, error) {
	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(raw), cyclonedx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode cyclonedx: %w", err)
	}

	doc := &Document{
		Raw:         raw,
		SpecVersion: bom.SpecVersion.String(),
		Tool:        toolName(bom),
	}

	direct := directDependencies(bom)

	flat := make([]cyclonedx.Component, 0, 64)
	if bom.Components != nil {
		flat = flatten(*bom.Components, flat)
	}

	seen := make(map[string]struct{}, len(flat))
	for _, component := range flat {
		if component.PackageURL == "" {
			continue
		}
		// A CycloneDX document may legitimately list the same PURL twice when
		// a package is reachable through several paths. Within one scan the
		// PURL is the primary key, so keep the first occurrence.
		if _, dup := seen[component.PackageURL]; dup {
			continue
		}
		seen[component.PackageURL] = struct{}{}

		identity, version, ecosystem, name := ParseIdentity(component.PackageURL)
		if version == "" {
			version = component.Version
		}
		if name == "" {
			name = component.Name
		}

		expression, licenses := extractLicenses(component.Licenses)

		_, isDirect := direct[component.BOMRef]
		doc.Components = append(doc.Components, Component{
			PURL:              component.PackageURL,
			Identity:          identity,
			Name:              name,
			Version:           version,
			Ecosystem:         ecosystem,
			Type:              string(component.Type),
			Licenses:          licenses,
			LicenseExpression: expression,
			Direct:            isDirect,
		})
	}

	SortComponents(doc.Components)
	return doc, nil
}

// flatten walks nested component trees; cdxgen nests transitive dependencies
// under their parent while syft emits a flat list, so both shapes must work.
func flatten(components []cyclonedx.Component, into []cyclonedx.Component) []cyclonedx.Component {
	for _, component := range components {
		into = append(into, component)
		if component.Components != nil {
			into = flatten(*component.Components, into)
		}
	}
	return into
}

// directDependencies returns the BOM refs the root component depends on. When
// the document carries no dependency graph the set is empty and every
// component is recorded as transitive rather than guessed at.
func directDependencies(bom *cyclonedx.BOM) map[string]struct{} {
	direct := make(map[string]struct{})
	if bom.Dependencies == nil || bom.Metadata == nil || bom.Metadata.Component == nil {
		return direct
	}
	root := bom.Metadata.Component.BOMRef
	for _, dependency := range *bom.Dependencies {
		if dependency.Ref != root || dependency.Dependencies == nil {
			continue
		}
		for _, ref := range *dependency.Dependencies {
			direct[ref] = struct{}{}
		}
	}
	return direct
}

// extractLicenses pulls both the SPDX expression form and the discrete-ID form
// out of a CycloneDX license list. CycloneDX allows either per entry.
func extractLicenses(licenses *cyclonedx.Licenses) (expression string, ids []string) {
	if licenses == nil {
		return "", nil
	}
	collected := make([]string, 0, len(*licenses))
	for _, choice := range *licenses {
		if choice.Expression != "" {
			if expression == "" {
				expression = choice.Expression
			}
			continue
		}
		if choice.License == nil {
			continue
		}
		if choice.License.ID != "" {
			collected = append(collected, choice.License.ID)
		} else if choice.License.Name != "" {
			collected = append(collected, choice.License.Name)
		}
	}
	return expression, normalizeLicenses(collected)
}

func toolName(bom *cyclonedx.BOM) string {
	if bom.Metadata == nil || bom.Metadata.Tools == nil {
		return ""
	}
	if components := bom.Metadata.Tools.Components; components != nil && len(*components) > 0 {
		tool := (*components)[0]
		if tool.Version != "" {
			return tool.Name + " " + tool.Version
		}
		return tool.Name
	}
	// CycloneDX <= 1.4 shape, still emitted by older syft builds.
	if tools := bom.Metadata.Tools.Tools; tools != nil && len(*tools) > 0 {
		tool := (*tools)[0]
		if tool.Version != "" {
			return tool.Name + " " + tool.Version
		}
		return tool.Name
	}
	return ""
}
