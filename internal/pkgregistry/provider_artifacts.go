package pkgregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
)

const (
	maxProviderDescriptorBytes = 256 << 10
	maxProviderSchemaBytes     = 16 << 20
	maxProviderInterfaces      = 128
	maxProviderResources       = 256
	maxProviderPermissions     = 256
	maxProviderSchemas         = 128
)

var (
	ErrProviderArtifactsRequired = errors.New("pkgregistry: exporting package requires provider artifacts")
	ErrProviderArtifactTooLarge  = errors.New("pkgregistry: provider artifact exceeds size limit")
	ErrProviderArtifactUnknown   = errors.New("pkgregistry: provider artifact contains unknown protobuf fields")
)

// loadedProviderArtifacts is deliberately private. Registry callers can copy an
// Entry, but they cannot mutate the parsed descriptor/schema objects that feed
// the kernel Catalog.
type loadedProviderArtifacts struct {
	descriptorWire []byte
	schemaWire     []byte
	parsed         *ipcregistry.ProviderArtifacts
}

func manifestExports(m Manifest) bool {
	for _, component := range m.Components {
		if len(component.Exports) != 0 {
			return true
		}
	}
	return false
}

func loadRequiredProviderArtifacts(root string, m Manifest, allowLegacyBridge bool) (*loadedProviderArtifacts, error) {
	if manifestExports(m) && m.Provider == nil {
		if allowLegacyBridge {
			return nil, nil
		}
		return nil, ErrProviderArtifactsRequired
	}
	return loadProviderArtifacts(root, m)
}

// loadProviderArtifacts reads the exact bytes that will be placed in the
// Catalog, rechecks their manifest digest, rejects unknown protobuf fields and
// delegates schema cross-validation to nervus-ipc.
func loadProviderArtifacts(root string, m Manifest) (*loadedProviderArtifacts, error) {
	if m.Provider == nil {
		return nil, nil
	}

	descriptorWire, err := readVerifiedArtifact(
		root, m.Provider.Descriptor, m.Digests[m.Provider.Descriptor], maxProviderDescriptorBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("pkgregistry: provider descriptor: %w", err)
	}
	schemaWire, err := readVerifiedArtifact(
		root, m.Provider.Schemas, m.Digests[m.Provider.Schemas], maxProviderSchemaBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("pkgregistry: provider schemas: %w", err)
	}

	var descriptor ipcv1.ProviderDescriptor
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(descriptorWire, &descriptor); err != nil {
		return nil, fmt.Errorf("pkgregistry: decode provider descriptor: %w", err)
	}
	var bundles ipcv1.InterfaceSchemaBundleSet
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(schemaWire, &bundles); err != nil {
		return nil, fmt.Errorf("pkgregistry: decode provider schemas: %w", err)
	}
	if messageHasUnknown(descriptor.ProtoReflect(), 0) || messageHasUnknown(bundles.ProtoReflect(), 0) {
		return nil, ErrProviderArtifactUnknown
	}

	parsed, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		return nil, fmt.Errorf("pkgregistry: validate provider artifacts: %w", err)
	}
	if parsed.Descriptor.GetPackageId() != m.PackageID {
		return nil, fmt.Errorf("pkgregistry: provider descriptor package %q does not match manifest %q",
			parsed.Descriptor.GetPackageId(), m.PackageID)
	}
	if len(parsed.Descriptor.GetInterfaces()) > maxProviderInterfaces ||
		len(parsed.Descriptor.GetResources()) > maxProviderResources ||
		len(parsed.Descriptor.GetPermissions()) > maxProviderPermissions ||
		parsed.Schemas.Len() > maxProviderSchemas {
		return nil, fmt.Errorf("%w: interfaces=%d resources=%d permissions=%d schemas=%d",
			ErrProviderArtifactTooLarge,
			len(parsed.Descriptor.GetInterfaces()),
			len(parsed.Descriptor.GetResources()),
			len(parsed.Descriptor.GetPermissions()),
			parsed.Schemas.Len(),
		)
	}

	return &loadedProviderArtifacts{
		descriptorWire: append([]byte(nil), descriptorWire...),
		schemaWire:     append([]byte(nil), schemaWire...),
		parsed:         parsed,
	}, nil
}

func readVerifiedArtifact(root, rel, wantHex string, limit int64) ([]byte, error) {
	if !validRelPath(rel) {
		return nil, fmt.Errorf("%w: %q", ErrUnsafeRelPath, rel)
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrIrregularFile, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrIrregularFile, path)
	}
	wire, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > limit {
		return nil, fmt.Errorf("%w: %s > %d bytes", ErrProviderArtifactTooLarge, rel, limit)
	}

	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("invalid sha256 digest for %q", rel)
	}
	got := sha256.Sum256(wire)
	if !bytes.Equal(got[:], want) {
		return nil, fmt.Errorf("%w: %s", ErrDigestMismatch, rel)
	}
	return wire, nil
}

func messageHasUnknown(message protoreflect.Message, depth int) bool {
	if !message.IsValid() || depth > 64 || len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind:
			value.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
				if messageHasUnknown(entry.Message(), depth+1) {
					unknown = true
					return false
				}
				return true
			})
		case field.IsList() && field.Kind() == protoreflect.MessageKind:
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if messageHasUnknown(list.Get(i).Message(), depth+1) {
					unknown = true
					break
				}
			}
		case field.Kind() == protoreflect.MessageKind:
			unknown = messageHasUnknown(value.Message(), depth+1)
		}
		return !unknown
	})
	return unknown
}
