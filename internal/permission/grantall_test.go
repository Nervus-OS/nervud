package permission

import "testing"

// skipIfGrantAll 跳过那些断言「安装期/运行期权限执法」的测试。
//
// V1GrantAll 打开时这些执法被有意短路（申请即授予、不要求用户确认），断言必然
// 不成立。选择跳过而不是删除或改断言：这些用例描述的是执法【恢复后】必须重新
// 成立的行为，删掉就等于把恢复时的验收标准一起丢了；改成断言"全部放行"则更糟
// —— 那会把一个临时放宽固化成看起来正确的规格。
//
// 翻回 V1GrantAll = false 时，这些用例应当【原样】重新变绿；任何一条没绿都说明
// 执法路径在放宽期间被改坏了。
func skipIfGrantAll(t *testing.T) {
	t.Helper()
	if V1GrantAll {
		t.Skip("V1GrantAll=true：权限执法被 v1 短路，本用例待执法恢复后重新生效")
	}
}

// TestV1GrantAll_IsDeliberate 在放宽期间守住"放宽的边界"本身。
//
// 它不断言 V1GrantAll 的取值（那由交付阶段决定），只断言放宽【没有溢出】到
// 「未声明也能用」：manifest 里没申请过的权限，install-set 里就没有，Allowed
// 必须仍然拒绝。这条是 v1 唯一还在执法的权限规则，比其余用例更该有锁。
func TestV1GrantAll_StillRequiresDeclaration(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{
		PackageID:   "com.example.hello",
		Permissions: []string{"perm.motion.control"},
	}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	// 申请过的：v1 下不再要求运行期用户确认，直接放行
	if !r.Allowed("com.example.hello", "perm.motion.control") {
		t.Error("已在 manifest 声明的权限在 V1GrantAll 下必须放行")
	}
	// 没申请过的：即便 V1GrantAll 也必须拒绝
	if r.Allowed("com.example.hello", "perm.camera.capture") {
		t.Error("未声明的权限即使在 V1GrantAll 下也必须拒绝")
	}
	// 压根没登记过的 Package：拒绝
	if r.Allowed("com.example.unknown", "perm.motion.control") {
		t.Error("未登记 Package 必须拒绝")
	}
}
