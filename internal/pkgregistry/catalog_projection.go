package pkgregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

var (
	// ErrCatalogUnavailable means pkgregistry was constructed without the one
	// central catalog that owns provider, permission, and resource definitions.
	ErrCatalogUnavailable = errors.New("pkgregistry: central catalog is unavailable")
	// ErrCatalogPublishConflict means somebody published a different catalog
	// revision after this module prepared its candidate. pkgregistry is the only
	// intended package-source writer, so this is an invariant violation and the
	// transaction must fail closed.
	ErrCatalogPublishConflict = errors.New("pkgregistry: catalog candidate base is stale")
)

const legacyPackageManagerID = "nervus.pkgmanagerd"

// projectCatalogSources converts only kernel-verified Entry state into the
// neutral catalog model. Source kind and signer identity are never taken from
// manifest fields or from the persisted grant ledger.
func projectCatalogSources(entries []Entry) ([]catalog.Source, error) {
	out := make([]catalog.Source, 0, len(entries))
	for _, entry := range entries {
		hasExports := manifestExports(entry.Manifest)
		if entry.provider == nil && !hasExports {
			continue
		}

		kind, err := catalogSourceKind(entry.Source)
		if err != nil {
			return nil, fmt.Errorf("package %q: %w", entry.Manifest.PackageID, err)
		}
		evidence := projectSignerEvidence(entry)
		source := catalog.Source{
			PackageID: entry.Manifest.PackageID,
			Kind:      kind,
			Trust:     entry.Trust,
			Signers:   evidence,
			Exports:   projectExports(entry.Manifest),
		}
		switch {
		case entry.provider != nil:
			if entry.provider.parsed == nil {
				return nil, fmt.Errorf("%w: package %q has no parsed artifacts",
					ErrInvalidProviderArtifacts, entry.Manifest.PackageID)
			}
			source.Artifacts = entry.provider.parsed
		case legacyPackageManagerEligible(entry):
			artifacts, bridgeErr := catalog.LegacyPackageManagerArtifacts()
			if bridgeErr != nil {
				return nil, fmt.Errorf("package %q: legacy package-manager artifacts: %w",
					entry.Manifest.PackageID, bridgeErr)
			}
			source.Artifacts = artifacts
		default:
			return nil, fmt.Errorf("%w: package %q",
				ErrProviderArtifactsRequired, entry.Manifest.PackageID)
		}
		out = append(out, source)
	}
	return out, nil
}

func catalogSourceKind(source Source) (catalog.SourceKind, error) {
	switch source {
	case SourceSystemImage:
		return catalog.SourceKindSystemImage, nil
	case SourceDynamicInstall:
		return catalog.SourceKindDynamicInstall, nil
	default:
		return catalog.SourceKindUnspecified, fmt.Errorf("%w: %q", ErrInvalidSource, source)
	}
}

func projectSignerEvidence(entry Entry) catalog.SignerEvidence {
	verified := make([]catalog.VerifiedSigner, len(entry.VerifiedSigners))
	roles := make([]string, 0, len(entry.VerifiedSigners))
	seenRoles := make(map[string]struct{}, len(entry.VerifiedSigners))
	for i, signer := range entry.VerifiedSigners {
		role := string(signer.Role)
		verified[i] = catalog.VerifiedSigner{
			Role:  role,
			KeyID: signer.KeyID,
		}
		if signer.KeyID != "" {
			if _, duplicate := seenRoles[role]; !duplicate {
				seenRoles[role] = struct{}{}
				roles = append(roles, role)
			}
		}
	}
	return catalog.SignerEvidence{
		Roles:           roles,
		VerifiedSigners: verified,
		DeveloperRootID: entry.DeveloperRootID,
	}
}

func projectExports(manifest Manifest) []catalog.ExportBinding {
	var out []catalog.ExportBinding
	for _, component := range manifest.Components {
		for _, export := range component.Exports {
			out = append(out, catalog.ExportBinding{
				ComponentID: component.ID,
				InterfaceID: export.Interface,
			})
		}
	}
	return out
}

// legacyPackageManagerEligible is deliberately the only artifact-less provider
// bridge. It requires an exact package/component/interface shape and an actual
// verified platform-release key identity; role text alone is insufficient.
func legacyPackageManagerEligible(entry Entry) bool {
	if entry.Manifest.PackageID != legacyPackageManagerID ||
		entry.Source != SourceSystemImage ||
		entry.Trust != identity.TrustPlatform ||
		entry.Manifest.Provider != nil {
		return false
	}
	exports := projectExports(entry.Manifest)
	if len(exports) != 1 ||
		exports[0].ComponentID != "main" ||
		exports[0].InterfaceID != catalog.InterfacePackageManager {
		return false
	}
	for _, signer := range entry.VerifiedSigners {
		if signer.Role == RolePlatformRelease && signer.KeyID != "" {
			return true
		}
	}
	return false
}

type preparedEntries struct {
	entries   []Entry
	candidate *catalog.Candidate
}

// prepareEntries validates the complete provider set, then recomputes every
// install-time grant against that exact immutable candidate snapshot.
func (m *Module) prepareEntries(ctx context.Context, entries []Entry) (preparedEntries, error) {
	if m.definitions == nil {
		return preparedEntries{}, ErrCatalogUnavailable
	}
	sources, err := projectCatalogSources(entries)
	if err != nil {
		return preparedEntries{}, err
	}
	candidate, err := m.definitions.Prepare(sources)
	if err != nil {
		return preparedEntries{}, fmt.Errorf("pkgregistry: prepare catalog: %w", err)
	}

	next := cloneEntries(entries)
	for i := range next {
		if next[i].RuntimeGeneration == 0 {
			next[i].RuntimeGeneration = candidate.Snapshot().Revision()
		}
		kind, kindErr := catalogSourceKind(next[i].Source)
		if kindErr != nil {
			return preparedEntries{}, fmt.Errorf("package %q: %w",
				next[i].Manifest.PackageID, kindErr)
		}
		granted, denied := m.perm.IntersectAt(
			candidate.Snapshot(),
			next[i].Manifest.Permissions,
			kind,
			next[i].Trust,
			projectSignerEvidence(next[i]),
		)
		next[i].GrantedPermissions = append([]string(nil), granted...)
		if len(denied) != 0 {
			m.aud.Record(ctx, audit.Event{
				Action:  "pkgregistry.IntersectAt",
				Subject: next[i].Manifest.PackageID,
				Denied:  true,
				Detail:  fmt.Sprintf("%v", denied),
			})
		}
	}
	return preparedEntries{entries: next, candidate: candidate}, nil
}

func cloneEntries(entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	for i, entry := range entries {
		out[i] = cloneEntry(entry)
	}
	return out
}

func upsertEntry(entries []Entry, replacement Entry) []Entry {
	out := make([]Entry, 0, len(entries)+1)
	for _, entry := range entries {
		if entry.Manifest.PackageID != replacement.Manifest.PackageID {
			out = append(out, entry)
		}
	}
	return append(out, replacement)
}

func removeEntryFrom(entries []Entry, packageID string) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Manifest.PackageID != packageID {
			out = append(out, entry)
		}
	}
	return out
}

func findEntry(entries []Entry, packageID string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Manifest.PackageID == packageID {
			return cloneEntry(entry), true
		}
	}
	return Entry{}, false
}

// publishCatalogLast publishes identity/package/grant projections first and the
// route-enabling catalog last. A provider can therefore never become routable
// before its freshly recomputed permission projection is visible.
func (m *Module) publishCatalogLast(
	ctx context.Context,
	previous []Entry,
	prepared preparedEntries,
) error {
	previousCatalog := m.definitions.Current()
	if err := m.idReg.Replace(projectIdentity(prepared.entries)); err != nil {
		return err
	}
	if err := m.registry.Replace(prepared.entries); err != nil {
		_ = m.idReg.Replace(projectIdentity(previous))
		return err
	}
	if err := m.perm.Replace(projectGrants(prepared.entries)); err != nil {
		_ = m.registry.Replace(previous)
		_ = m.idReg.Replace(projectIdentity(previous))
		return err
	}
	if m.definitions.Publish(prepared.candidate) {
		m.revokeChangedResources(previousCatalog, prepared.candidate.Snapshot())
		return nil
	}

	// A stale candidate means the catalog no longer corresponds to either
	// projection set. Emptying install grants is the only generally safe
	// fallback; restoring old grants could authorize a concurrently published
	// definition that was never part of the old transaction.
	if err := m.perm.Replace(nil); err != nil {
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.PublishCatalog.failClosed",
			Denied: true,
			Err:    err,
		})
	}
	_ = m.registry.Replace(previous)
	_ = m.idReg.Replace(projectIdentity(previous))
	return ErrCatalogPublishConflict
}

func (m *Module) revokeChangedResources(previous, next *catalog.Snapshot) {
	if m.transferRevoker == nil {
		return
	}
	for _, revoked := range catalog.RevokedResources(previous, next) {
		m.transferRevoker.RevokeResource(revoked.Handle, revoked.Generation)
	}
}
