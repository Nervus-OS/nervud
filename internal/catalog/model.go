// Package catalog owns the immutable, data-driven definition catalog shared by
// endpoint, permission, resource, and the IPC method gate.
//
// The package deliberately imports none of those consumers (nor pkgregistry).
// Package loading projects verified package state into the neutral Source type
// below, while all consumers read the same Snapshot instance.
package catalog

import (
	"sort"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nervus-os/nervud/internal/identity"
)

const (
	// KernelPackageID is the synthetic provider identity used for interfaces
	// implemented inside nervud itself.
	KernelPackageID = "nervus.kernel"

	InterfaceMotionBase      = "nervus.interface.motion.base"
	InterfaceManipulatorArm  = "nervus.interface.manipulator.arm"
	InterfacePackageManager  = "nervus.interface.pkg.manager"
	InterfaceSafetyControl   = "nervus.interface.safety.control"
	InterfaceTransferControl = "nervus.interface.transfer.control"
	InterfacePower           = "nervus.interface.power"

	// InterfaceResourceDirectory 是 Catalog 自己的只读视图.
	//
	// 它列在这里而 nervus.interface.camera 不在, 区别不是"谁更重要": 目录
	// 描述的是 Catalog 本身, 除了内核没有第二个实现者; 而摄像头是一项能力,
	// 由签名的系统服务用 ProviderArtifacts 声明, 内核不该认识它.
	InterfaceResourceDirectory = "nervus.interface.resource.directory"

	// InterfaceOperationControl 是长任务的查询/取消/回报面.
	//
	// 它与资源目录同理由列在这里: Operation 的状态机归内核所有, 除了 nervud
	// 没有第二个实现者. 摄像头那类能力由签名的系统服务用 ProviderArtifacts
	// 声明, 内核不该认识.
	InterfaceOperationControl = "nervus.interface.operation.control"

	ResourceMotionBase     = "nervus.resource.motion.base"
	ResourceManipulatorArm = "nervus.resource.manipulator.arm"
)

// SourceKind describes where a definition source came from. Its value is a
// kernel conclusion; it must never be copied from a manifest field.
type SourceKind uint8

const (
	SourceKindUnspecified SourceKind = iota
	SourceKindKernel
	SourceKindSystemImage
	SourceKindDynamicInstall
)

func (k SourceKind) valid() bool {
	return k == SourceKindKernel || k == SourceKindSystemImage || k == SourceKindDynamicInstall
}

// VerifiedSigner is one signature that pkgregistry has already verified.
// KeyID is identity; Role is authority. A role alone is not a signing identity.
type VerifiedSigner struct {
	Role  string
	KeyID string
}

// SignerEvidence is the neutral, verified signer projection used by policy.
// DeveloperRootID remains stable across an accepted developer-key rotation.
type SignerEvidence struct {
	Roles           []string
	VerifiedSigners []VerifiedSigner
	DeveloperRootID string
}

func (s SignerEvidence) HasRole(role string) bool {
	for _, candidate := range s.Roles {
		if candidate == role {
			return true
		}
	}
	for _, candidate := range s.VerifiedSigners {
		if candidate.Role == role {
			return true
		}
	}
	return false
}

func (s SignerEvidence) HasStableIdentity() bool {
	if s.DeveloperRootID != "" {
		return true
	}
	for _, signer := range s.VerifiedSigners {
		if signer.KeyID != "" {
			return true
		}
	}
	return false
}

// SameIdentity reports whether two signer sets share an actual verified signing
// identity. It intentionally does not treat equal roles as equal identities.
func (s SignerEvidence) SameIdentity(other SignerEvidence) bool {
	if s.DeveloperRootID != "" && s.DeveloperRootID == other.DeveloperRootID {
		return true
	}
	for _, left := range s.VerifiedSigners {
		if left.KeyID == "" {
			continue
		}
		for _, right := range other.VerifiedSigners {
			if left.KeyID == right.KeyID {
				return true
			}
		}
	}
	return false
}

// ExportBinding is the manifest-side statement that one component exports an
// interface. ProviderDescriptor owns schema and policy; this binding owns
// runtime implementation membership.
type ExportBinding struct {
	ComponentID string
	InterfaceID string
}

// KernelBuiltin defines a schema-less method table implemented by nervud. It is
// only accepted on SourceKindKernel. This is intentionally narrow: ordinary
// providers must always use signed ProviderArtifacts.
type KernelBuiltin struct {
	ComponentID        string
	InterfaceID        string
	Major              uint32
	RequiredPermission string
	Methods            []*ipcv1.MethodMeta
}

// Source is the complete neutral input for one package/provider.
//
// Artifacts must already come from bytes covered by the verified package
// digest. Builder still revalidates their internal consistency and applies
// kernel-owned trust, namespace, risk, and conflict policy.
type Source struct {
	PackageID string
	Kind      SourceKind
	Trust     identity.TrustProfile
	Signers   SignerEvidence
	Exports   []ExportBinding
	Artifacts *ipcregistry.ProviderArtifacts

	KernelBuiltins []KernelBuiltin
}

// DefinitionOwner records the independent identity decision behind a catalog
// definition. It is immutable once stored in a Snapshot.
type DefinitionOwner struct {
	PackageID string
	Kind      SourceKind
	Trust     identity.TrustProfile
	Signers   SignerEvidence
}

// InterfaceDefinition is the canonical contract for one interface major.
type InterfaceDefinition struct {
	InterfaceID string
	Major       uint32

	SchemaHash []byte

	RequiredPermission      string
	ResourceRiskFloor       ipcv1.RiskClass
	CompatibleResourceTypes []string
	DefaultResourceType     string
	DefaultResourceRole     string

	KernelBuiltin        bool
	Owner                DefinitionOwner
	DefinitionGeneration uint64
}

// MethodDefinition is fully resolved at build time. Message descriptors are
// immutable protobuf descriptors; Meta is cloned whenever it crosses the API.
type MethodDefinition struct {
	InterfaceID string
	Major       uint32
	MethodID    uint32

	Meta        *ipcv1.MethodMeta
	Request     protoreflect.MessageDescriptor
	Response    protoreflect.MessageDescriptor
	ErrorDetail protoreflect.MessageDescriptor

	KernelBuiltin        bool
	CatalogRevision      uint64
	DefinitionGeneration uint64
	ProviderGeneration   uint64
}

// EventDefinition 是一个可订阅事件的权威定义, 地位同 MethodDefinition.
//
// 订阅准入靠它回答三件事: 谁能订阅 (Meta.RequiredPermission), 推送多快
//
//	(Meta.MaxEventsPerSecond), 缺口意味着什么 (Meta.DeliveryClass).
//
// 三者都不在事件载荷里, 也不能由 Provider 在推送时自报.
type EventDefinition struct {
	InterfaceID string
	Major       uint32
	EventID     uint32

	Meta    *ipcv1.EventMeta
	Payload protoreflect.MessageDescriptor

	KernelBuiltin        bool
	CatalogRevision      uint64
	DefinitionGeneration uint64
	ProviderGeneration   uint64
}

// ProviderInterface proves that PackageID is an accepted runtime implementer of
// Definition. Canonical Interface existence alone is not implementation
// authority.
type ProviderInterface struct {
	PackageID     string
	ComponentID   string
	Definition    InterfaceDefinition
	ProviderOwner DefinitionOwner

	KernelBuiltin        bool
	DefinitionGeneration uint64
}

// PermissionDefinition contains both wire declaration and effective kernel
// policy. MinimumTrust is already max(declared floor, risk/mode platform floor).
type PermissionDefinition struct {
	ID                   string
	GrantMode            ipcv1.GrantMode
	RiskClass            ipcv1.RiskClass
	DeclaredMinimumTrust ipcv1.PermissionTrustFloor
	MinimumTrust         identity.TrustProfile
	RequiredSignerRole   string
	Group                string
	DisplayNameZhCN      string
	DisplayNameEN        string
	DescriptionZhCN      string
	DescriptionEN        string
	Owner                DefinitionOwner
	DefinitionGeneration uint64
}

// ResourceDefinition is one stable resource instance. StableRole is also its
// public handle in the latest IPC model. ManagerPackageID is empty for a
// bootstrap definition that has not yet been claimed by a real provider.
type ResourceDefinition struct {
	Handle           string
	ResourceType     string
	StableRole       string
	AccessMode       ipcv1.ResourceAccessMode
	RiskClass        ipcv1.RiskClass
	ManagerPackageID string
	Owner            DefinitionOwner
	ManagerOwner     DefinitionOwner

	// Labels 是该资源的语义标签, 供 ResourceSelector.labels 匹配.
	//
	// StableRole 是板级配置的产物 (这块板上前视摄像头叫 cam.front 还是
	// camera0), App 不该依赖它. 标签让 App 按语义选设备, 换板不用改 App.
	Labels map[string]string

	DefinitionGeneration uint64
}

type interfaceKey struct {
	id    string
	major uint32
}

type providerInterfaceKey struct {
	pkg   string
	id    string
	major uint32
}

type resourceKey struct {
	resourceType string
	stableRole   string
}

type interfaceRecord struct {
	def     InterfaceDefinition
	methods map[uint32]MethodDefinition
	events  map[uint32]EventDefinition
}

type providerInterfaceRecord struct {
	def ProviderInterface
}

// Snapshot is an immutable catalog revision. All maps and records stay private;
// query methods return defensive copies of slice/protobuf fields.
type Snapshot struct {
	revision uint64

	interfaces         map[interfaceKey]interfaceRecord
	providerInterfaces map[providerInterfaceKey]providerInterfaceRecord
	permissions        map[string]PermissionDefinition
	resources          map[resourceKey]ResourceDefinition
	resourcesByHandle  map[string]ResourceDefinition
}

func (s *Snapshot) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.revision
}

func (s *Snapshot) Interface(interfaceID string, major uint32) (InterfaceDefinition, bool) {
	if s == nil {
		return InterfaceDefinition{}, false
	}
	record, ok := s.interfaces[interfaceKey{id: interfaceID, major: major}]
	if !ok {
		return InterfaceDefinition{}, false
	}
	return cloneInterfaceDefinition(record.def), true
}

func (s *Snapshot) ProviderInterface(
	packageID string,
	interfaceID string,
	major uint32,
) (ProviderInterface, bool) {
	if s == nil {
		return ProviderInterface{}, false
	}
	record, ok := s.providerInterfaces[providerInterfaceKey{
		pkg: packageID, id: interfaceID, major: major,
	}]
	if !ok {
		return ProviderInterface{}, false
	}
	return cloneProviderInterface(record.def), true
}

// ProviderInterfaces returns every catalog-authorized provider implementation
// of interfaceID whose major is in the inclusive range. Results are ordered by
// preferred major (highest first), then package and component identity, so a
// caller never depends on map iteration order. Every result is a defensive
// copy.
func (s *Snapshot) ProviderInterfaces(
	interfaceID string,
	minMajor uint32,
	maxMajor uint32,
) []ProviderInterface {
	if s == nil || interfaceID == "" || maxMajor < minMajor {
		return nil
	}
	out := make([]ProviderInterface, 0)
	for key, record := range s.providerInterfaces {
		if key.id != interfaceID || key.major < minMajor || key.major > maxMajor {
			continue
		}
		out = append(out, cloneProviderInterface(record.def))
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.Definition.Major != right.Definition.Major {
			return left.Definition.Major > right.Definition.Major
		}
		if left.PackageID != right.PackageID {
			return left.PackageID < right.PackageID
		}
		return left.ComponentID < right.ComponentID
	})
	return out
}

func (s *Snapshot) Method(interfaceID string, major, methodID uint32) (MethodDefinition, bool) {
	if s == nil {
		return MethodDefinition{}, false
	}
	record, ok := s.interfaces[interfaceKey{id: interfaceID, major: major}]
	if !ok {
		return MethodDefinition{}, false
	}
	method, ok := record.methods[methodID]
	if !ok {
		return MethodDefinition{}, false
	}
	out := cloneMethodDefinition(method)
	out.CatalogRevision = s.revision
	return out, true
}

func (s *Snapshot) Event(interfaceID string, major, eventID uint32) (EventDefinition, bool) {
	if s == nil {
		return EventDefinition{}, false
	}
	record, ok := s.interfaces[interfaceKey{id: interfaceID, major: major}]
	if !ok {
		return EventDefinition{}, false
	}
	event, ok := record.events[eventID]
	if !ok {
		return EventDefinition{}, false
	}
	out := cloneEventDefinition(event)
	out.CatalogRevision = s.revision
	return out, true
}

// ProviderEvent 证明 packageID 确实是该接口的已接受实现者, 再取事件定义.
//
// 与 ProviderMethod 同规: 接口里定义了这个事件, 不等于这个 Provider
// 被允许提供它.
func (s *Snapshot) ProviderEvent(
	packageID string,
	interfaceID string,
	major uint32,
	eventID uint32,
) (EventDefinition, bool) {
	if s == nil {
		return EventDefinition{}, false
	}
	provider, ok := s.providerInterfaces[providerInterfaceKey{
		pkg: packageID, id: interfaceID, major: major,
	}]
	if !ok {
		return EventDefinition{}, false
	}
	event, ok := s.Event(interfaceID, major, eventID)
	if !ok {
		return EventDefinition{}, false
	}
	event.KernelBuiltin = provider.def.KernelBuiltin
	event.ProviderGeneration = provider.def.DefinitionGeneration
	return event, true
}

func (s *Snapshot) ProviderMethod(
	packageID string,
	interfaceID string,
	major uint32,
	methodID uint32,
) (MethodDefinition, bool) {
	if s == nil {
		return MethodDefinition{}, false
	}
	provider, ok := s.providerInterfaces[providerInterfaceKey{
		pkg: packageID, id: interfaceID, major: major,
	}]
	if !ok {
		return MethodDefinition{}, false
	}
	method, ok := s.Method(interfaceID, major, methodID)
	if !ok {
		return MethodDefinition{}, false
	}
	method.KernelBuiltin = provider.def.KernelBuiltin
	method.ProviderGeneration = provider.def.DefinitionGeneration
	return method, true
}

func (s *Snapshot) Permission(id string) (PermissionDefinition, bool) {
	if s == nil {
		return PermissionDefinition{}, false
	}
	def, ok := s.permissions[id]
	if !ok {
		return PermissionDefinition{}, false
	}
	return clonePermissionDefinition(def), true
}

func (s *Snapshot) ResolveResource(
	resourceType string,
	stableRole string,
) (ResourceDefinition, bool) {
	if s == nil {
		return ResourceDefinition{}, false
	}
	def, ok := s.resources[resourceKey{resourceType: resourceType, stableRole: stableRole}]
	if !ok {
		return ResourceDefinition{}, false
	}
	return cloneResourceDefinition(def), true
}

func (s *Snapshot) ResourceByHandle(handle string) (ResourceDefinition, bool) {
	if s == nil {
		return ResourceDefinition{}, false
	}
	def, ok := s.resourcesByHandle[handle]
	if !ok {
		return ResourceDefinition{}, false
	}
	return cloneResourceDefinition(def), true
}

// RevokedResource identifies the exact old resource authority invalidated by a
// catalog publication. Generation is required because a new definition may
// reuse the same stable handle before revocation observers finish running.
type RevokedResource struct {
	Handle     string
	Generation uint64
}

// RevokedResources returns old handle/generation pairs whose authority
// disappeared or changed semantics in next. New handles are intentionally not
// included because no route or lease could have been authorized by them in the
// previous revision.
func RevokedResources(previous, next *Snapshot) []RevokedResource {
	if previous == nil {
		return nil
	}
	changed := make([]RevokedResource, 0)
	for handle, old := range previous.resourcesByHandle {
		current, ok := next.resourcesByHandle[handle]
		if !ok || current.DefinitionGeneration != old.DefinitionGeneration {
			changed = append(changed, RevokedResource{
				Handle: handle, Generation: old.DefinitionGeneration,
			})
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].Handle < changed[j].Handle })
	return changed
}

func cloneSource(in Source) Source {
	out := in
	out.Signers = cloneSignerEvidence(in.Signers)
	out.Exports = append([]ExportBinding(nil), in.Exports...)
	out.KernelBuiltins = make([]KernelBuiltin, len(in.KernelBuiltins))
	for i, builtin := range in.KernelBuiltins {
		out.KernelBuiltins[i] = builtin
		out.KernelBuiltins[i].Methods = cloneMethodMetas(builtin.Methods)
	}
	if in.Artifacts != nil {
		out.Artifacts = &ipcregistry.ProviderArtifacts{
			Schemas: in.Artifacts.Schemas,
		}
		if in.Artifacts.Descriptor != nil {
			out.Artifacts.Descriptor = proto.Clone(in.Artifacts.Descriptor).(*ipcv1.ProviderDescriptor)
		}
	}
	return out
}

func cloneSignerEvidence(in SignerEvidence) SignerEvidence {
	out := in
	out.Roles = append([]string(nil), in.Roles...)
	out.VerifiedSigners = append([]VerifiedSigner(nil), in.VerifiedSigners...)
	return out
}

func cloneOwner(in DefinitionOwner) DefinitionOwner {
	out := in
	out.Signers = cloneSignerEvidence(in.Signers)
	return out
}

func cloneInterfaceDefinition(in InterfaceDefinition) InterfaceDefinition {
	out := in
	out.SchemaHash = append([]byte(nil), in.SchemaHash...)
	out.CompatibleResourceTypes = append([]string(nil), in.CompatibleResourceTypes...)
	out.Owner = cloneOwner(in.Owner)
	return out
}

func cloneMethodDefinition(in MethodDefinition) MethodDefinition {
	out := in
	if in.Meta != nil {
		out.Meta = proto.Clone(in.Meta).(*ipcv1.MethodMeta)
	}
	return out
}

func cloneProviderInterface(in ProviderInterface) ProviderInterface {
	out := in
	out.Definition = cloneInterfaceDefinition(in.Definition)
	out.ProviderOwner = cloneOwner(in.ProviderOwner)
	return out
}

func clonePermissionDefinition(in PermissionDefinition) PermissionDefinition {
	out := in
	out.Owner = cloneOwner(in.Owner)
	return out
}

func cloneEventDefinition(in EventDefinition) EventDefinition {
	out := in
	if in.Meta != nil {
		out.Meta = proto.Clone(in.Meta).(*ipcv1.EventMeta)
	}
	return out
}

func cloneResourceDefinition(in ResourceDefinition) ResourceDefinition {
	out := in
	out.Owner = cloneOwner(in.Owner)
	out.ManagerOwner = cloneOwner(in.ManagerOwner)
	out.Labels = cloneLabels(in.Labels)
	return out
}

// cloneLabels 深拷贝标签 map. Snapshot 是不可变的, 返回内部 map 会让消费者
// 能就地改写一份已发布的 Catalog.
func cloneLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// sameLabels 比较两组标签. 用于 sameResourceContract - 两个 Provider 声明同一个
// 资源时, 标签也必须一致, 否则 App 按标签选到的会是哪一个取决于发布顺序.
func sameLabels(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for k, v := range left {
		if other, ok := right[k]; !ok || other != v {
			return false
		}
	}
	return true
}

func cloneMethodMetas(in []*ipcv1.MethodMeta) []*ipcv1.MethodMeta {
	out := make([]*ipcv1.MethodMeta, len(in))
	for i, meta := range in {
		if meta != nil {
			out[i] = proto.Clone(meta).(*ipcv1.MethodMeta)
		}
	}
	return out
}

func normalizedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
