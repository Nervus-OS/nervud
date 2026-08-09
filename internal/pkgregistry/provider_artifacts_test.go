package pkgregistry

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestMessageHasUnknown_ScalarValuedMapDoesNotPanic 钉住 map<string,string> 不会 panic.
//
// # 这条 bug 让 nervud 起不来
//
// protoreflect 里, 一个 map 字段的 FieldDescriptor.Kind() 恒为 MessageKind
// (map 在 wire 上就是 repeated 的合成 entry 消息), 【与它的值类型无关】.
// 因此按 Kind() 判断会让 map<string,string> 落进"这是个子消息"的分支,
// 而那里对一个 string 值调 value.Message() —— protoreflect 直接 panic.
//
// ProviderDescriptor.resources[].labels 正是 map<string,string>
// (provider_descriptor.proto:196). 于是任何声明了带 labels 的资源的系统包
// 都会让开机扫描 panic: scanSystemImage -> loadProviderArtifacts ->
// messageHasUnknown, 表现是 nervud 直接退出 status=2, 整个系统起不来.
func TestMessageHasUnknown_ScalarValuedMapDoesNotPanic(t *testing.T) {
	descriptor := &ipcv1.ProviderDescriptor{
		Resources: []*ipcv1.ManagedResource{{
			StableRole: "cam.front",
			// 关键: 值是 string 而不是消息
			Labels: map[string]string{"nervus.camera.facing": "front"},
		}},
	}
	// 不 recover: panic 就该让这条测试失败并显示栈, 那正是线上看到的东西
	if messageHasUnknown(descriptor.ProtoReflect(), 0) {
		t.Error("一个字段全部已知的消息被判成含未知字段")
	}
}

// TestMessageHasUnknown_StillDetectsUnknownInNestedMessage: 修复不能把检测本身
// 弄坏 —— 它存在的意义是拒掉带未知字段的 provider 产物 (那意味着产物由更新版本
// 的 schema 生成, 而本内核不认识其中一部分, 静默忽略会让契约悄悄漂移).
func TestMessageHasUnknown_StillDetectsUnknownInNestedMessage(t *testing.T) {
	descriptor := &ipcv1.ProviderDescriptor{
		Resources: []*ipcv1.ManagedResource{{StableRole: "cam.front"}},
	}
	// 往嵌套消息里塞一段未知字段 (field 50000, varint)
	descriptor.Resources[0].ProtoReflect().SetUnknown(
		protoreflect.RawFields([]byte{0x80, 0x86, 0x18, 0x01}))

	if !messageHasUnknown(descriptor.ProtoReflect(), 0) {
		t.Error("嵌套消息里的未知字段没被发现 —— 这道门形同虚设")
	}
}

// TestMessageHasUnknown_DetectsUnknownInRepeatedMessage: repeated 消息里的未知
// 字段仍要被发现.
//
// 与标量 map 那条用例合起来说明修复是"按值类型分派"而不是"跳过所有复合字段".
//
// 【没有为"消息值 map"写用例, 是因为整套 proto 里没有这种字段】: 现有的 map
// 全是 map<string,string> (provider_descriptor / envelope / resourcedir 各处的
// labels), 而 InterfaceSchemaBundleSet.bundles 是 repeated 而非 map. 为此造一个
// 只存在于测试里的 .proto 类型, 换来的覆盖不对应任何真实数据 —— 修复里那条
// MessageKind 分支本身已经是按值类型判的.
func TestMessageHasUnknown_DetectsUnknownInRepeatedMessage(t *testing.T) {
	bundles := &ipcv1.InterfaceSchemaBundleSet{
		Bundles: []*ipcv1.InterfaceSchemaBundle{{InterfaceId: "nervus.interface.demo"}},
	}
	bundles.Bundles[0].ProtoReflect().SetUnknown(
		protoreflect.RawFields([]byte{0x80, 0x86, 0x18, 0x01}))

	if !messageHasUnknown(bundles.ProtoReflect(), 0) {
		t.Error("repeated 消息里的未知字段没被发现")
	}
}
