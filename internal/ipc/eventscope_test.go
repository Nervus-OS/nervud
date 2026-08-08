package ipc

import "testing"

//

func testConns(n int) []*conn {
	out := make([]*conn, n)
	for i := range out {
		out[i] = &conn{}
	}
	return out
}

func TestEventScopes_OnlyOwnerIsAllowed(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 100, alice)

	if !s.allows(provider, 7, 100, alice) {
		t.Fatal("unexpected ipc result")
	}
	if s.allows(provider, 7, 100, bob) {
		t.Fatal("unexpected ipc result")
	}
}

func TestEventScopes_UnregisteredIsRejected(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)

	if s.allows(c[0], 7, 100, c[1]) {
		t.Fatal("unexpected ipc result; scope")
	}

	if s.allows(c[0], 7, 0, c[1]) {
		t.Fatal("unexpected ipc result; scope 0")
	}
}

func TestEventScopes_EndpointIsPartOfTheKey(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)

	if s.allows(provider, 8, 1, owner) {
		t.Fatal("unexpected ipc result; endpoint scope")
	}
}

func TestEventScopes_ReleaseTakesEffect(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 100, owner)
	s.release(provider, 7, 100)

	if s.allows(provider, 7, 100, owner) {
		t.Fatal("unexpected ipc result")
	}
	if s.len() != 0 {
		t.Fatalf("unexpected ipc result; value = %d", s.len())
	}
}

func TestEventScopes_RebindTransfersOwnership(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 100, alice)
	s.bind(provider, 7, 100, bob)

	if s.allows(provider, 7, 100, alice) {
		t.Fatal("unexpected ipc result")
	}
	if !s.allows(provider, 7, 100, bob) {
		t.Fatal("unexpected ipc result")
	}

	if s.len() != 1 {
		t.Fatalf("unexpected ipc result; value = %d, want 1", s.len())
	}
}

func TestEventScopes_ProviderDisconnectClearsAll(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, other, owner := c[0], c[1], c[2]

	s.bind(provider, 7, 1, owner)
	s.bind(provider, 8, 2, owner)
	s.bind(other, 9, 3, owner)

	s.closeProvider(provider)

	if s.len() != 1 {
		t.Fatalf("unexpected ipc result; value = %d, want 1 Provider", s.len())
	}
	if !s.allows(other, 9, 3, owner) {
		t.Fatal("unexpected ipc result; Provider")
	}
}

//

func TestEventScopes_OwnerDisconnectClearsAll(t *testing.T) {
	s := newEventScopes()
	c := testConns(3)
	provider, alice, bob := c[0], c[1], c[2]

	s.bind(provider, 7, 1, alice)
	s.bind(provider, 7, 2, bob)

	s.closeOwner(alice)

	if s.allows(provider, 7, 1, alice) {
		t.Fatal("unexpected ipc result")
	}
	if !s.allows(provider, 7, 2, bob) {
		t.Fatal("unexpected ipc result")
	}
	if s.len() != 1 {
		t.Fatalf("unexpected ipc result; value = %d, want 1", s.len())
	}
}

//

func TestEventScopes_EndpointCloseClearsItsScopesOnly(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)
	s.bind(provider, 7, 2, owner)
	s.bind(provider, 8, 3, owner)

	s.closeEndpoint(provider, 7)

	if s.len() != 1 {
		t.Fatalf("unexpected ipc result; value = %d, want 1", s.len())
	}
	if !s.allows(provider, 8, 3, owner) {
		t.Fatal("unexpected ipc result; endpoint")
	}
}

//

func TestEventScopes_CleanupIsIdempotent(t *testing.T) {
	s := newEventScopes()
	c := testConns(2)
	provider, owner := c[0], c[1]

	s.bind(provider, 7, 1, owner)
	s.closeProvider(provider)
	s.closeProvider(provider)
	s.closeOwner(owner)

	if s.len() != 0 {
		t.Fatalf("unexpected ipc result; value = %d", s.len())
	}

	s.bind(provider, 7, 1, owner)
	if !s.allows(provider, 7, 1, owner) {
		t.Fatal("unexpected ipc result")
	}
}
