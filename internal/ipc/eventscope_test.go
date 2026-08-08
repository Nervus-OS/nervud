package ipc

import "testing"

// 本文件验的是【事件实例归属表】：一路摄像头上开着好几条 stream 时，
// 谁有资格订阅哪一条。
//
// 这里用裸 *conn 指针当身份，不建真连接——表本身只按指针比较，
// 建连接只会让用例变慢而不增加任何覆盖。

func testConns(n int) []*conn {
	out := make([]*conn, n)
	for i := range out {
		out[i] = &conn{}
	}
	return out
}

// 登记之后本人订得上，别人订不上。这是整张表存在的理由。
func TestEventScopes_OnlyOwnerIsAllowed(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 100, alice)

	if !s.allows(provider, 7, 100, alice) {
		t.Fatal("登记的所有者订不上自己的实例")
	}
	if s.allows(provider, 7, 100, bob) {
		t.Fatal("别人订上了不属于它的实例")
	}
}

// 【未登记即拒绝】。fail closed 的方向在这里格外要紧：放行一个没登记的 scope
// 等于回到不分实例的广播，而那正是本表要解决的问题。
func TestEventScopes_UnregisteredIsRejected(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)

	if s.allows(c[0], 7, 100, c[1]) {
		t.Fatal("没登记过的 scope 被放行了")
	}
	// scope 0 永远不放行：0 表示「不分实例」。
	if s.allows(c[0], 7, 0, c[1]) {
		t.Fatal("scope 0 被放行了")
	}
}

// 同一个 Provider 的不同 endpoint 是不同的键——一个服务可以同时提供好几路
// 摄像头，它们的 stream_id 各自从 1 开始。
func TestEventScopes_EndpointIsPartOfTheKey(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)

	if s.allows(provider, 8, 1, owner) {
		t.Fatal("另一个 endpoint 上的同号 scope 被放行了")
	}
}

// 撤销之后立刻失效。
func TestEventScopes_ReleaseTakesEffect(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 100, owner)
	s.release(provider, 7, 100)

	if s.allows(provider, 7, 100, owner) {
		t.Fatal("撤销之后仍然订得上")
	}
	if s.len() != 0 {
		t.Fatalf("撤销后剩余 %d 条登记", s.len())
	}
}

// 【重复登记覆盖，不拒绝】。Provider 关掉再开同一条流是它自己的事；
// 拒绝会让它不得不先撤销再登记，而中间那一小段里订阅会失败。
func TestEventScopes_RebindTransfersOwnership(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 100, alice)
	s.bind(provider, 7, 100, bob)

	if s.allows(provider, 7, 100, alice) {
		t.Fatal("旧所有者仍然订得上")
	}
	if !s.allows(provider, 7, 100, bob) {
		t.Fatal("新所有者订不上")
	}
	// 旧所有者那侧的索引也要摘干净，否则它断开时会去删一条已经不属于它的登记。
	if s.len() != 1 {
		t.Fatalf("剩余 %d 条登记, want 1", s.len())
	}
}

// Provider 断开：它登记的实例全都不再存在。
func TestEventScopes_ProviderDisconnectClearsAll(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, other, owner := c[0], c[1], c[2]

	s.bind(provider, 7, 1, owner)
	s.bind(provider, 8, 2, owner)
	s.bind(other, 9, 3, owner)

	s.closeProvider(provider)

	if s.len() != 1 {
		t.Fatalf("剩余 %d 条, want 1（只该留下别的 Provider 那条）", s.len())
	}
	if !s.allows(other, 9, 3, owner) {
		t.Fatal("误伤了另一个 Provider 的登记")
	}
}

// 订阅方断开：它的实例随之消失（stream 绑在连接上）。
//
// 【两个方向都要清】：少了这一边，一个反复连断的 App 会在表里留下永远
// 清不掉的条目。
func TestEventScopes_OwnerDisconnectClearsAll(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 1, alice)
	s.bind(provider, 7, 2, bob)

	s.closeOwner(alice)

	if s.allows(provider, 7, 1, alice) {
		t.Fatal("断开的所有者的登记还在")
	}
	if !s.allows(provider, 7, 2, bob) {
		t.Fatal("误伤了另一个所有者的登记")
	}
	if s.len() != 1 {
		t.Fatalf("剩余 %d 条, want 1", s.len())
	}
}

// endpoint 撤下时清掉它上面的全部实例。
//
// 【不能只等连接断开】：一个长驻 Provider 反复注册撤销 endpoint 会让登记
// 无界累积。
func TestEventScopes_EndpointCloseClearsItsScopesOnly(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)
	s.bind(provider, 7, 2, owner)
	s.bind(provider, 8, 3, owner)

	s.closeEndpoint(provider, 7)

	if s.len() != 1 {
		t.Fatalf("剩余 %d 条, want 1", s.len())
	}
	if !s.allows(provider, 8, 3, owner) {
		t.Fatal("误伤了另一个 endpoint 的登记")
	}
}

// 清理必须把两张反向索引都摘干净，否则第二次断开会去删已经不存在的条目。
//
// 这条用例的价值在于它会抓住「只清了 owner 索引没清 provider 索引」那类
// 半吊子实现——表面上第一次清理是对的，泄漏要到第二次才显形。
func TestEventScopes_CleanupIsIdempotent(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)
	s.closeProvider(provider)
	s.closeProvider(provider)
	s.closeOwner(owner)

	if s.len() != 0 {
		t.Fatalf("剩余 %d 条登记", s.len())
	}
	// 重新登记仍然正常——索引没被前面的清理弄坏。
	s.bind(provider, 7, 1, owner)
	if !s.allows(provider, 7, 1, owner) {
		t.Fatal("清理之后再登记失效了")
	}
}
