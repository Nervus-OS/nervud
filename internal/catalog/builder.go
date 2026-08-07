package catalog

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nervus-os/nervud/internal/identity"
)

const (
	roleDeveloper         = "developer"
	rolePlatformRelease   = "platform-release"
	rolePlatformSystemApp = "platform-systemapp"
	roleOEMService        = "oem-service"
	roleOEMApp            = "oem-app"
	roleOEMTrustSoftware  = "oem-trust-software"
)

// Policy is intentionally closed today. Keeping it as an explicit value makes
// the security-policy dependency visible without exposing runtime knobs that
// could weaken namespace or risk checks.
type Policy struct{}

func DefaultPolicy() Policy { return Policy{} }

func (Policy) validate() error { return nil }

type Builder struct {
	policy Policy
}

func NewBuilder(policy Policy) *Builder {
	return &Builder{policy: policy}
}

// Build validates all sources and constructs a complete immutable Snapshot.
// Any error rejects the entire candidate; previous is never modified.
func (b *Builder) Build(previous *Snapshot, sources []Source) (*Snapshot, error) {
	if b == nil {
		return nil, errors.New("catalog: nil builder")
	}
	if err := b.policy.validate(); err != nil {
		return nil, fmt.Errorf("catalog: invalid policy: %w", err)
	}
	revision := uint64(1)
	if previous != nil {
		if previous.revision == math.MaxUint64 {
			return nil, errors.New("catalog: revision exhausted")
		}
		revision = previous.revision + 1
	}

	ordered := make([]Source, len(sources))
	for i, source := range sources {
		ordered[i] = normalizeSource(cloneSource(source))
		if err := validateSourceShape(ordered[i]); err != nil {
			return nil, &SourceError{PackageID: ordered[i].PackageID, Err: err}
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := sourceRank(ordered[i]), sourceRank(ordered[j])
		if left != right {
			return left < right
		}
		return ordered[i].PackageID < ordered[j].PackageID
	})

	next := &Snapshot{
		revision:           revision,
		interfaces:         make(map[interfaceKey]interfaceRecord),
		providerInterfaces: make(map[providerInterfaceKey]providerInterfaceRecord),
		permissions:        make(map[string]PermissionDefinition),
		resources:          make(map[resourceKey]ResourceDefinition),
		resourcesByHandle:  make(map[string]ResourceDefinition),
	}

	seenPackages := make(map[string]struct{}, len(ordered))
	for _, source := range ordered {
		if _, duplicate := seenPackages[source.PackageID]; duplicate {
			return nil, sourceErrorf(source.PackageID, "duplicate source package")
		}
		seenPackages[source.PackageID] = struct{}{}

		if source.Artifacts != nil {
			if err := b.addArtifacts(next, source); err != nil {
				return nil, &SourceError{PackageID: source.PackageID, Err: err}
			}
		} else if source.Kind != SourceKindKernel && len(source.Exports) != 0 {
			return nil, sourceErrorf(source.PackageID, "exports interfaces without ProviderArtifacts")
		}

		if len(source.KernelBuiltins) != 0 {
			if source.Kind != SourceKindKernel {
				return nil, sourceErrorf(source.PackageID, "non-kernel source declares kernel builtins")
			}
			for _, builtin := range source.KernelBuiltins {
				if err := b.addKernelBuiltin(next, source, builtin); err != nil {
					return nil, sourceErrorf(source.PackageID,
						"builtin %q: %w", builtin.InterfaceID, err)
				}
			}
		}
	}

	if err := validateGlobalPermissionReferences(next); err != nil {
		return nil, err
	}
	assignDefinitionGenerations(previous, next)
	if err := buildResourceHandleIndex(next); err != nil {
		return nil, err
	}
	return next, nil
}

func (b *Builder) addArtifacts(next *Snapshot, source Source) error {
	artifacts := source.Artifacts
	if artifacts.Descriptor == nil || artifacts.Schemas == nil {
		return errors.New("ProviderArtifacts requires descriptor and schemas")
	}
	if artifacts.Descriptor.GetPackageId() != source.PackageID {
		return fmt.Errorf("descriptor package_id %q does not match source package_id",
			artifacts.Descriptor.GetPackageId())
	}
	if err := ipcregistry.ValidateProviderArtifacts(artifacts.Descriptor, artifacts.Schemas); err != nil {
		return fmt.Errorf("invalid ProviderArtifacts: %w", err)
	}

	exports, err := indexExports(source.Exports)
	if err != nil {
		return err
	}
	declaredInterfaces := make(map[string]struct{}, len(artifacts.Descriptor.GetInterfaces()))
	for _, iface := range artifacts.Descriptor.GetInterfaces() {
		declaredInterfaces[iface.GetInterfaceId()] = struct{}{}
	}
	for interfaceID := range exports {
		if _, ok := declaredInterfaces[interfaceID]; !ok {
			return fmt.Errorf("manifest exports undeclared interface %q", interfaceID)
		}
	}
	if source.Kind != SourceKindKernel {
		for interfaceID := range declaredInterfaces {
			if _, ok := exports[interfaceID]; !ok {
				return fmt.Errorf("descriptor interface %q is not exported by a component", interfaceID)
			}
		}
	}

	owner := ownerFromSource(source)
	for _, wire := range artifacts.Descriptor.GetPermissions() {
		def, err := b.permissionDefinition(source, owner, wire)
		if err != nil {
			return err
		}
		if previous, duplicate := next.permissions[def.ID]; duplicate {
			return fmt.Errorf("permission %q conflicts between %q and %q",
				def.ID, previous.Owner.PackageID, source.PackageID)
		}
		next.permissions[def.ID] = def
	}

	for _, wire := range artifacts.Descriptor.GetInterfaces() {
		versions, err := interfaceVersions(wire)
		if err != nil {
			return fmt.Errorf("interface %q: %w", wire.GetInterfaceId(), err)
		}
		majors := make([]uint32, 0, len(versions))
		for major := range versions {
			majors = append(majors, major)
		}
		sort.Slice(majors, func(i, j int) bool { return majors[i] < majors[j] })

		for _, major := range majors {
			schema, ok := artifacts.Schemas.Lookup(wire.GetInterfaceId(), major)
			if !ok {
				return fmt.Errorf("interface %q@%d schema disappeared after validation",
					wire.GetInterfaceId(), major)
			}
			record, err := b.interfaceRecord(source, owner, wire, schema)
			if err != nil {
				return err
			}
			key := interfaceKey{id: wire.GetInterfaceId(), major: major}
			canonical, exists := next.interfaces[key]
			if exists {
				if !sameInterfaceContract(canonical, record) {
					return fmt.Errorf("interface %q@%d conflicts with definition owned by %q",
						key.id, key.major, canonical.def.Owner.PackageID)
				}
				if isPlatformNamespace(key.id) && !canImplementStandard(source) {
					return fmt.Errorf("source lacks authority to implement standard interface %q@%d",
						key.id, key.major)
				}
			} else {
				if err := authorizeNewInterface(source, record); err != nil {
					return err
				}
				next.interfaces[key] = record
			}

			componentID, exported := exports[wire.GetInterfaceId()]
			if exported {
				providerKey := providerInterfaceKey{
					pkg: source.PackageID, id: wire.GetInterfaceId(), major: major,
				}
				if _, duplicate := next.providerInterfaces[providerKey]; duplicate {
					return fmt.Errorf("duplicate provider membership for %q %q@%d",
						source.PackageID, wire.GetInterfaceId(), major)
				}
				next.providerInterfaces[providerKey] = providerInterfaceRecord{
					def: ProviderInterface{
						PackageID:     source.PackageID,
						ComponentID:   componentID,
						Definition:    next.interfaces[key].def,
						ProviderOwner: owner,
						KernelBuiltin: source.Kind == SourceKindKernel,
					},
				}
			}
		}
	}

	for _, wire := range artifacts.Descriptor.GetResources() {
		if err := b.addResource(next, source, owner, wire); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) interfaceRecord(
	source Source,
	owner DefinitionOwner,
	wire *ipcv1.ProvidedInterface,
	schema *ipcregistry.Schema,
) (interfaceRecord, error) {
	compatible := normalizedStrings(wire.GetCompatibleResourceTypes())
	def := InterfaceDefinition{
		InterfaceID:             wire.GetInterfaceId(),
		Major:                   schema.Major(),
		SchemaHash:              schema.Hash(),
		RequiredPermission:      wire.GetRequiredPermission(),
		ResourceRiskFloor:       wire.GetResourceRiskFloor(),
		CompatibleResourceTypes: compatible,
		DefaultResourceType:     wire.GetDefaultResourceType(),
		DefaultResourceRole:     wire.GetDefaultResourceRole(),
		Owner:                   owner,
	}
	methods := make(map[uint32]MethodDefinition)
	maxRisk := def.ResourceRiskFloor
	for methodID, meta := range schema.Methods() {
		if meta.GetRiskClass() > maxRisk {
			maxRisk = meta.GetRiskClass()
		}
		method, err := resolveMethodDefinition(def.InterfaceID, def.Major, schema, meta)
		if err != nil {
			return interfaceRecord{}, err
		}
		methods[methodID] = method
	}
	if err := authorizeRisk(source, maxRisk, false); err != nil {
		return interfaceRecord{}, fmt.Errorf("interface %q@%d: %w", def.InterfaceID, def.Major, err)
	}
	return interfaceRecord{def: def, methods: methods}, nil
}

func resolveMethodDefinition(
	interfaceID string,
	major uint32,
	schema *ipcregistry.Schema,
	meta *ipcv1.MethodMeta,
) (MethodDefinition, error) {
	method := MethodDefinition{
		InterfaceID: interfaceID,
		Major:       major,
		MethodID:    meta.GetMethodId(),
		Meta:        proto.Clone(meta).(*ipcv1.MethodMeta),
	}
	var err error
	if method.Request, err = findMessage(schema, meta.GetRequestType()); err != nil {
		return MethodDefinition{}, fmt.Errorf("interface %q@%d method %d request: %w",
			interfaceID, major, meta.GetMethodId(), err)
	}
	if method.Response, err = findMessage(schema, meta.GetResponseType()); err != nil {
		return MethodDefinition{}, fmt.Errorf("interface %q@%d method %d response: %w",
			interfaceID, major, meta.GetMethodId(), err)
	}
	if method.ErrorDetail, err = findMessage(schema, meta.GetErrorDetailType()); err != nil {
		return MethodDefinition{}, fmt.Errorf("interface %q@%d method %d error detail: %w",
			interfaceID, major, meta.GetMethodId(), err)
	}
	return method, nil
}

func findMessage(schema *ipcregistry.Schema, name string) (protoreflect.MessageDescriptor, error) {
	if name == "" {
		return nil, nil
	}
	desc, err := schema.Files().FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, err
	}
	message, ok := desc.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is not a message", name)
	}
	return message, nil
}

func (b *Builder) permissionDefinition(
	source Source,
	owner DefinitionOwner,
	wire *ipcv1.DefinedPermission,
) (PermissionDefinition, error) {
	if err := authorizePermissionNamespace(source, wire.GetId()); err != nil {
		return PermissionDefinition{}, err
	}
	if role := wire.GetRequiredSignerRole(); role != "" && !knownSignerRole(role) {
		return PermissionDefinition{}, fmt.Errorf("permission %q requires unknown signer role %q",
			wire.GetId(), role)
	}
	minimum, err := effectiveMinimumTrust(wire)
	if err != nil {
		return PermissionDefinition{}, fmt.Errorf("permission %q: %w", wire.GetId(), err)
	}
	if err := authorizeRisk(source, wire.GetRiskClass(), false); err != nil {
		return PermissionDefinition{}, fmt.Errorf("permission %q: %w", wire.GetId(), err)
	}
	return PermissionDefinition{
		ID:                   wire.GetId(),
		GrantMode:            wire.GetGrantMode(),
		RiskClass:            wire.GetRiskClass(),
		DeclaredMinimumTrust: wire.GetMinimumTrust(),
		MinimumTrust:         minimum,
		RequiredSignerRole:   wire.GetRequiredSignerRole(),
		Group:                wire.GetGroup(),
		DisplayNameZhCN:      wire.GetDisplayName().GetZhCn(),
		DisplayNameEN:        wire.GetDisplayName().GetEn(),
		DescriptionZhCN:      wire.GetDescription().GetZhCn(),
		DescriptionEN:        wire.GetDescription().GetEn(),
		Owner:                owner,
	}, nil
}

func (b *Builder) addResource(
	next *Snapshot,
	source Source,
	owner DefinitionOwner,
	wire *ipcv1.ManagedResource,
) error {
	if err := authorizeResource(source, next, wire); err != nil {
		return err
	}
	def := ResourceDefinition{
		Handle:       wire.GetStableRole(),
		ResourceType: wire.GetResourceType(),
		StableRole:   wire.GetStableRole(),
		AccessMode:   wire.GetAccessMode(),
		RiskClass:    wire.GetRiskClass(),
		Labels:       cloneLabels(wire.GetLabels()),
		Owner:        owner,
	}
	if source.Kind != SourceKindKernel {
		def.ManagerPackageID = source.PackageID
		def.ManagerOwner = owner
	}
	key := resourceKey{resourceType: def.ResourceType, stableRole: def.StableRole}
	existing, exists := next.resources[key]
	if !exists {
		next.resources[key] = def
		return nil
	}
	if !sameResourceContract(existing, def) {
		return fmt.Errorf("resource type=%q role=%q conflicts with definition owned by %q",
			def.ResourceType, def.StableRole, existing.Owner.PackageID)
	}
	if existing.ManagerPackageID != "" && def.ManagerPackageID != "" &&
		existing.ManagerPackageID != def.ManagerPackageID {
		return fmt.Errorf("resource handle %q has multiple managers %q and %q",
			def.Handle, existing.ManagerPackageID, def.ManagerPackageID)
	}
	if existing.ManagerPackageID == "" && def.ManagerPackageID != "" {
		existing.ManagerPackageID = def.ManagerPackageID
		existing.ManagerOwner = def.ManagerOwner
		next.resources[key] = existing
	}
	return nil
}

func (b *Builder) addKernelBuiltin(next *Snapshot, source Source, builtin KernelBuiltin) error {
	if builtin.InterfaceID == "" || builtin.Major == 0 || builtin.ComponentID == "" {
		return errors.New("kernel builtin requires component, interface, and nonzero major")
	}
	owner := ownerFromSource(source)
	def := InterfaceDefinition{
		InterfaceID:        builtin.InterfaceID,
		Major:              builtin.Major,
		RequiredPermission: builtin.RequiredPermission,
		KernelBuiltin:      true,
		Owner:              owner,
	}
	methods := make(map[uint32]MethodDefinition, len(builtin.Methods))
	for _, meta := range builtin.Methods {
		if err := validateKernelMethodMeta(meta); err != nil {
			return err
		}
		if _, duplicate := methods[meta.GetMethodId()]; duplicate {
			return fmt.Errorf("duplicate method id %d", meta.GetMethodId())
		}
		methods[meta.GetMethodId()] = MethodDefinition{
			InterfaceID:   builtin.InterfaceID,
			Major:         builtin.Major,
			MethodID:      meta.GetMethodId(),
			Meta:          proto.Clone(meta).(*ipcv1.MethodMeta),
			KernelBuiltin: true,
		}
	}
	record := interfaceRecord{def: def, methods: methods}
	key := interfaceKey{id: builtin.InterfaceID, major: builtin.Major}
	if existing, duplicate := next.interfaces[key]; duplicate {
		if !sameInterfaceContract(existing, record) {
			return fmt.Errorf("conflicts with existing interface definition")
		}
	} else {
		next.interfaces[key] = record
	}
	providerKey := providerInterfaceKey{
		pkg: source.PackageID, id: builtin.InterfaceID, major: builtin.Major,
	}
	if _, duplicate := next.providerInterfaces[providerKey]; duplicate {
		return errors.New("duplicate kernel provider membership")
	}
	next.providerInterfaces[providerKey] = providerInterfaceRecord{def: ProviderInterface{
		PackageID:     source.PackageID,
		ComponentID:   builtin.ComponentID,
		Definition:    next.interfaces[key].def,
		ProviderOwner: owner,
		KernelBuiltin: true,
	}}
	return nil
}

func validateKernelMethodMeta(meta *ipcv1.MethodMeta) error {
	if meta == nil || meta.GetMethodId() == 0 {
		return errors.New("kernel builtin method id 0 is reserved")
	}
	if meta.GetRiskClass() < ipcv1.RiskClass_RISK_CLASS_NORMAL ||
		meta.GetRiskClass() > ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY {
		return fmt.Errorf("kernel builtin method %d has invalid risk class", meta.GetMethodId())
	}
	if meta.GetRequestType() != "" || meta.GetResponseType() != "" || meta.GetErrorDetailType() != "" {
		return fmt.Errorf("schema-less kernel builtin method %d must use empty request/response/detail types",
			meta.GetMethodId())
	}
	if meta.GetTransfer() != nil {
		return fmt.Errorf("schema-less kernel builtin method %d cannot create transfers", meta.GetMethodId())
	}
	return nil
}

func indexExports(exports []ExportBinding) (map[string]string, error) {
	out := make(map[string]string, len(exports))
	for _, export := range exports {
		if export.InterfaceID == "" || export.ComponentID == "" {
			return nil, errors.New("export binding requires component_id and interface_id")
		}
		if previous, duplicate := out[export.InterfaceID]; duplicate {
			return nil, fmt.Errorf("interface %q is exported by both %q and %q",
				export.InterfaceID, previous, export.ComponentID)
		}
		out[export.InterfaceID] = export.ComponentID
	}
	return out, nil
}

// interfaceVersions 把接口声明的各 major 展开成 major -> 契约哈希。
//
// 只认 interface_versions：v1 的 versions/schema_hash 组合已移除（proto 里
// 那两个字段号已 reserved）。registry.ParseProviderArtifacts 已经做过同样的
// 校验，这里再走一遍是因为 Builder 也接受 kernel bootstrap 那条不经 Parse 的路径。
func interfaceVersions(wire *ipcv1.ProvidedInterface) (map[uint32][]byte, error) {
	versions := wire.GetInterfaceVersions()
	if len(versions) == 0 {
		return nil, errors.New("no interface versions")
	}
	out := make(map[uint32][]byte, len(versions))
	for _, version := range versions {
		out[version.GetMajor()] = append([]byte(nil), version.GetSchemaHash()...)
	}
	return out, nil
}

func validateSourceShape(source Source) error {
	if source.PackageID == "" {
		return errors.New("catalog: source has empty package id")
	}
	if !source.Kind.valid() {
		return fmt.Errorf("catalog: source %q has invalid kind %d", source.PackageID, source.Kind)
	}
	if !source.Trust.Valid() {
		return fmt.Errorf("catalog: source %q has invalid trust %d", source.PackageID, source.Trust)
	}
	if source.Kind == SourceKindKernel && source.PackageID != KernelPackageID {
		return fmt.Errorf("catalog: kernel source must use package id %q", KernelPackageID)
	}
	if source.Kind == SourceKindKernel && source.Trust != identity.TrustPlatform {
		return fmt.Errorf("catalog: kernel source must have platform trust")
	}
	if source.Kind == SourceKindDynamicInstall && source.Trust != identity.TrustOrdinary {
		return fmt.Errorf("catalog: dynamically installed source %q must have ordinary trust",
			source.PackageID)
	}
	verifiedRoles := make(map[string]struct{}, len(source.Signers.VerifiedSigners))
	for _, signer := range source.Signers.VerifiedSigners {
		if signer.KeyID == "" {
			return fmt.Errorf("catalog: source %q has a verified signer with empty key id",
				source.PackageID)
		}
		if !knownSignerRole(signer.Role) {
			return fmt.Errorf("catalog: source %q has unknown verified signer role %q",
				source.PackageID, signer.Role)
		}
		verifiedRoles[signer.Role] = struct{}{}
	}
	for _, role := range source.Signers.Roles {
		if !knownSignerRole(role) {
			return fmt.Errorf("catalog: source %q has unknown signer role %q",
				source.PackageID, role)
		}
		if _, ok := verifiedRoles[role]; !ok {
			return fmt.Errorf("catalog: source %q signer role %q has no verified signer identity",
				source.PackageID, role)
		}
	}
	if source.Kind != SourceKindKernel && !source.Signers.HasStableIdentity() {
		return fmt.Errorf("catalog: source %q has no stable verified signer identity", source.PackageID)
	}
	return nil
}

func ownerFromSource(source Source) DefinitionOwner {
	return DefinitionOwner{
		PackageID: source.PackageID,
		Kind:      source.Kind,
		Trust:     source.Trust,
		Signers:   cloneSignerEvidence(source.Signers),
	}
}

func normalizeSource(source Source) Source {
	source.Signers.Roles = normalizedStrings(source.Signers.Roles)
	sort.Slice(source.Signers.VerifiedSigners, func(i, j int) bool {
		left, right := source.Signers.VerifiedSigners[i], source.Signers.VerifiedSigners[j]
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		return left.KeyID < right.KeyID
	})
	sort.Slice(source.Exports, func(i, j int) bool {
		if source.Exports[i].InterfaceID != source.Exports[j].InterfaceID {
			return source.Exports[i].InterfaceID < source.Exports[j].InterfaceID
		}
		return source.Exports[i].ComponentID < source.Exports[j].ComponentID
	})
	return source
}

func sourceRank(source Source) int {
	switch {
	case source.Kind == SourceKindKernel:
		return 0
	case isPlatformRelease(source):
		return 1
	case isOEMService(source):
		return 2
	case source.Kind == SourceKindSystemImage:
		return 3
	default:
		return 4
	}
}

func isPlatformRelease(source Source) bool {
	return source.Kind == SourceKindKernel ||
		(source.Kind == SourceKindSystemImage &&
			source.Trust == identity.TrustPlatform &&
			source.Signers.HasRole(rolePlatformRelease))
}

func isOEMService(source Source) bool {
	return isPlatformRelease(source) ||
		(source.Kind == SourceKindSystemImage &&
			source.Trust >= identity.TrustOEM &&
			source.Signers.HasRole(roleOEMService))
}

func canImplementStandard(source Source) bool {
	return isPlatformRelease(source) || isOEMService(source)
}

func authorizePermissionNamespace(source Source, id string) error {
	if strings.HasPrefix(id, "perm.") {
		if !isPlatformRelease(source) {
			return fmt.Errorf("source lacks platform-release authority to define permission %q", id)
		}
		return nil
	}
	if !strings.HasPrefix(id, source.PackageID+".") {
		return fmt.Errorf("private permission %q is outside package namespace %q", id, source.PackageID)
	}
	return nil
}

func authorizeNewInterface(source Source, record interfaceRecord) error {
	if isPlatformNamespace(record.def.InterfaceID) {
		if !isPlatformRelease(source) {
			return fmt.Errorf("source lacks platform-release authority to define standard interface %q",
				record.def.InterfaceID)
		}
		return nil
	}
	if !strings.HasPrefix(record.def.InterfaceID, source.PackageID+".") {
		return fmt.Errorf("private interface %q is outside package namespace %q",
			record.def.InterfaceID, source.PackageID)
	}
	return nil
}

func authorizeResource(source Source, next *Snapshot, wire *ipcv1.ManagedResource) error {
	if err := authorizeRisk(source, wire.GetRiskClass(), true); err != nil {
		return fmt.Errorf("resource type=%q role=%q: %w",
			wire.GetResourceType(), wire.GetStableRole(), err)
	}
	if err := authorizeResourceLabels(source, wire); err != nil {
		return fmt.Errorf("resource type=%q role=%q: %w",
			wire.GetResourceType(), wire.GetStableRole(), err)
	}
	if !isPlatformNamespace(wire.GetResourceType()) {
		if !strings.HasPrefix(wire.GetResourceType(), source.PackageID+".") {
			return fmt.Errorf("private resource type %q is outside package namespace %q",
				wire.GetResourceType(), source.PackageID)
		}
		return nil
	}
	if isPlatformRelease(source) {
		return nil
	}
	if !isOEMService(source) {
		return fmt.Errorf("source lacks OEM-service authority for standard resource type %q",
			wire.GetResourceType())
	}
	if !catalogKnowsResourceType(next, wire.GetResourceType()) {
		return fmt.Errorf("OEM source cannot introduce unknown standard resource type %q",
			wire.GetResourceType())
	}
	return nil
}

// authorizeResourceLabels 对标签键施加与接口/权限同一套命名空间规则。
//
// 标签是【App 选设备的依据】：一个厂商如果能随手声明 nervus.camera.facing=front，
// 它就能把自己的摄像头伪装成平台语义下的前视摄像头，让按标准标签选设备的 App
// 选到它。所以平台标签只有 platform-release 能定义，私有标签必须在自己命名空间下——
// 与接口、权限、资源类型完全同规。
func authorizeResourceLabels(source Source, wire *ipcv1.ManagedResource) error {
	for key := range wire.GetLabels() {
		if key == "" {
			return errors.New("label key is empty")
		}
		if isPlatformNamespace(key) {
			if !isPlatformRelease(source) {
				return fmt.Errorf(
					"source lacks platform-release authority to define standard label %q", key)
			}
			continue
		}
		if !strings.HasPrefix(key, source.PackageID+".") {
			return fmt.Errorf("private label %q is outside package namespace %q",
				key, source.PackageID)
		}
	}
	return nil
}

func catalogKnowsResourceType(snapshot *Snapshot, resourceType string) bool {
	for _, record := range snapshot.interfaces {
		for _, compatible := range record.def.CompatibleResourceTypes {
			if compatible == resourceType {
				return true
			}
		}
	}
	return false
}

func authorizeRisk(source Source, risk ipcv1.RiskClass, resource bool) error {
	if source.Kind == SourceKindKernel {
		return nil
	}
	switch risk {
	case ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY:
		if !isPlatformRelease(source) {
			return errors.New("critical-safety definition requires platform-release system authority")
		}
	case ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL:
		if !isOEMService(source) {
			return errors.New("physical-control definition requires OEM-service system authority")
		}
	case ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE:
		if resource && !isOEMService(source) {
			return errors.New("privacy-sensitive resource requires OEM-service system authority")
		}
	}
	return nil
}

func isPlatformNamespace(id string) bool {
	return strings.HasPrefix(id, "nervus.")
}

func knownSignerRole(role string) bool {
	switch role {
	case roleDeveloper, rolePlatformRelease, rolePlatformSystemApp,
		roleOEMService, roleOEMApp, roleOEMTrustSoftware:
		return true
	default:
		return false
	}
}

func effectiveMinimumTrust(wire *ipcv1.DefinedPermission) (identity.TrustProfile, error) {
	minimum, err := trustFloor(wire.GetMinimumTrust())
	if err != nil {
		return identity.TrustUnspecified, err
	}
	riskFloor := identity.TrustOrdinary
	if wire.GetRiskClass() == ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY {
		riskFloor = identity.TrustPlatform
	}
	switch wire.GetGrantMode() {
	case ipcv1.GrantMode_GRANT_MODE_NORMAL:
		if wire.GetRiskClass() != ipcv1.RiskClass_RISK_CLASS_NORMAL {
			return identity.TrustUnspecified, errors.New("NORMAL grant is only valid for normal-risk permissions")
		}
	case ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
		ipcv1.GrantMode_GRANT_MODE_SIGNATURE:
		// The declared/risk floor is sufficient.
	case ipcv1.GrantMode_GRANT_MODE_PRIVILEGED:
		if riskFloor < identity.TrustOEM {
			riskFloor = identity.TrustOEM
		}
	case ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY:
		riskFloor = identity.TrustPlatform
	default:
		return identity.TrustUnspecified, fmt.Errorf("unsupported grant mode %d", wire.GetGrantMode())
	}
	if minimum < riskFloor {
		minimum = riskFloor
	}
	return minimum, nil
}

func trustFloor(value ipcv1.PermissionTrustFloor) (identity.TrustProfile, error) {
	switch value {
	case ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_UNSPECIFIED,
		ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY:
		return identity.TrustOrdinary, nil
	case ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM:
		return identity.TrustOEM, nil
	case ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM:
		return identity.TrustPlatform, nil
	default:
		return identity.TrustUnspecified, fmt.Errorf("invalid permission trust floor %d", value)
	}
}

func validateGlobalPermissionReferences(snapshot *Snapshot) error {
	check := func(owner, permission string) error {
		if permission == "" {
			return nil
		}
		if _, ok := snapshot.permissions[permission]; !ok {
			return fmt.Errorf("catalog: %s references undefined permission %q", owner, permission)
		}
		return nil
	}
	for key, record := range snapshot.interfaces {
		label := fmt.Sprintf("interface %q@%d", key.id, key.major)
		if err := check(label, record.def.RequiredPermission); err != nil {
			return err
		}
		for methodID, method := range record.methods {
			if err := check(fmt.Sprintf("%s method %d", label, methodID),
				method.Meta.GetRequiredPermission()); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameInterfaceContract(left, right interfaceRecord) bool {
	leftDef, rightDef := left.def, right.def
	leftDef.Owner = DefinitionOwner{}
	rightDef.Owner = DefinitionOwner{}
	leftDef.DefinitionGeneration = 0
	rightDef.DefinitionGeneration = 0
	if !reflect.DeepEqual(leftDef, rightDef) || len(left.methods) != len(right.methods) {
		return false
	}
	for methodID, leftMethod := range left.methods {
		rightMethod, ok := right.methods[methodID]
		if !ok || !sameMethodContract(leftMethod, rightMethod) {
			return false
		}
	}
	return true
}

func sameMethodContract(left, right MethodDefinition) bool {
	if left.InterfaceID != right.InterfaceID || left.Major != right.Major ||
		left.MethodID != right.MethodID || left.KernelBuiltin != right.KernelBuiltin {
		return false
	}
	return proto.Equal(left.Meta, right.Meta)
}

func sameResourceContract(left, right ResourceDefinition) bool {
	return left.Handle == right.Handle &&
		left.ResourceType == right.ResourceType &&
		left.StableRole == right.StableRole &&
		left.AccessMode == right.AccessMode &&
		left.RiskClass == right.RiskClass &&
		// 标签也算契约的一部分：两个 Provider 声明同一个资源却给了不同标签，
		// App 按标签选到哪一个就取决于发布顺序了
		sameLabels(left.Labels, right.Labels)
}

func assignDefinitionGenerations(previous, next *Snapshot) {
	for key, record := range next.interfaces {
		generation := next.revision
		if previous != nil {
			if old, ok := previous.interfaces[key]; ok &&
				sameInterfaceRecordSemantics(old, record) {
				generation = old.def.DefinitionGeneration
			}
		}
		record.def.DefinitionGeneration = generation
		for methodID, method := range record.methods {
			method.DefinitionGeneration = generation
			record.methods[methodID] = method
		}
		next.interfaces[key] = record
	}

	for key, record := range next.providerInterfaces {
		canonical := next.interfaces[interfaceKey{id: key.id, major: key.major}].def
		record.def.Definition = canonical
		generation := next.revision
		if previous != nil {
			if old, ok := previous.providerInterfaces[key]; ok &&
				sameProviderInterfaceSemantics(old.def, record.def) &&
				old.def.Definition.DefinitionGeneration == canonical.DefinitionGeneration {
				generation = old.def.DefinitionGeneration
			}
		}
		record.def.DefinitionGeneration = generation
		next.providerInterfaces[key] = record
	}

	for id, def := range next.permissions {
		generation := next.revision
		if previous != nil {
			if old, ok := previous.permissions[id]; ok && samePermissionSemantics(old, def) {
				generation = old.DefinitionGeneration
			}
		}
		def.DefinitionGeneration = generation
		next.permissions[id] = def
	}

	for key, def := range next.resources {
		generation := next.revision
		if previous != nil {
			if old, ok := previous.resources[key]; ok && sameResourceSemantics(old, def) {
				generation = old.DefinitionGeneration
			}
		}
		def.DefinitionGeneration = generation
		next.resources[key] = def
	}
}

func sameInterfaceRecordSemantics(left, right interfaceRecord) bool {
	if !sameInterfaceContract(left, right) {
		return false
	}
	return reflect.DeepEqual(normalizeOwner(left.def.Owner), normalizeOwner(right.def.Owner))
}

func sameProviderInterfaceSemantics(left, right ProviderInterface) bool {
	return left.PackageID == right.PackageID &&
		left.ComponentID == right.ComponentID &&
		left.KernelBuiltin == right.KernelBuiltin &&
		reflect.DeepEqual(normalizeOwner(left.ProviderOwner), normalizeOwner(right.ProviderOwner))
}

func samePermissionSemantics(left, right PermissionDefinition) bool {
	left.DefinitionGeneration = 0
	right.DefinitionGeneration = 0
	left.Owner = normalizeOwner(left.Owner)
	right.Owner = normalizeOwner(right.Owner)
	return reflect.DeepEqual(left, right)
}

func sameResourceSemantics(left, right ResourceDefinition) bool {
	left.DefinitionGeneration = 0
	right.DefinitionGeneration = 0
	left.Owner = normalizeOwner(left.Owner)
	right.Owner = normalizeOwner(right.Owner)
	return reflect.DeepEqual(left, right)
}

func normalizeOwner(owner DefinitionOwner) DefinitionOwner {
	owner.Signers.Roles = normalizedStrings(owner.Signers.Roles)
	sort.Slice(owner.Signers.VerifiedSigners, func(i, j int) bool {
		left, right := owner.Signers.VerifiedSigners[i], owner.Signers.VerifiedSigners[j]
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		return left.KeyID < right.KeyID
	})
	return owner
}

func buildResourceHandleIndex(snapshot *Snapshot) error {
	for key, def := range snapshot.resources {
		if previous, duplicate := snapshot.resourcesByHandle[def.Handle]; duplicate {
			return fmt.Errorf("catalog: resource handle %q collides between type=%q role=%q and type=%q role=%q",
				def.Handle, previous.ResourceType, previous.StableRole, key.resourceType, key.stableRole)
		}
		snapshot.resourcesByHandle[def.Handle] = def
	}
	return nil
}

// EqualSchemaHash is a small consumer helper for RegisterEndpoint checks.
/*func EqualSchemaHash(def InterfaceDefinition, candidate []byte) bool {
	return bytes.Equal(def.SchemaHash, candidate)
}*/
