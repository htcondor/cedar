package security

import (
	"slices"
	"testing"
)

// The bounding set a parent mints must reach the server's enforcement path,
// which reads it from the cached entry's policy on resumption. validCommands
// does not bound anything -- dispatch re-evaluates authorization against the
// current Authorizer -- so without this a child could run whatever the
// Authorizer allows condor@parent.
func TestMintInheritableSessionLimitsAreEnforceable(t *testing.T) {
	const cmd = 74000

	t.Run("limits reach the session policy", func(t *testing.T) {
		GetSessionCache().Clear()
		sid, _, err := MintInheritableSessionWithLimits("<127.0.0.1:9999>", []string{"READ"}, cmd)
		if err != nil {
			t.Fatalf("MintInheritableSessionWithLimits: %v", err)
		}
		entry, ok := GetSessionCache().LookupNonExpired(sid)
		if !ok {
			t.Fatal("minted session is not in the global cache")
		}
		got, ok := entry.Policy().EvaluateAttrString(AttrLimitAuthorization)
		if !ok {
			t.Fatalf("session policy carries no %s, so nothing bounds the child", AttrLimitAuthorization)
		}
		if limits := parseLimitAuthorization(got); !slices.Equal(limits, []string{"READ"}) {
			t.Errorf("limits = %q, want [READ]", limits)
		}
	})

	t.Run("a command id alone bounds nothing", func(t *testing.T) {
		GetSessionCache().Clear()
		sid, _, err := MintInheritableSession("<127.0.0.1:9999>", cmd)
		if err != nil {
			t.Fatalf("MintInheritableSession: %v", err)
		}
		entry, ok := GetSessionCache().LookupNonExpired(sid)
		if !ok {
			t.Fatal("minted session is not in the global cache")
		}
		// Documented behaviour, asserted so the doc cannot drift back into
		// promising a boundary: passing a command id yields no bounding set.
		if _, ok := entry.Policy().EvaluateAttrString(AttrLimitAuthorization); ok {
			t.Error("a command id produced a bounding set; the doc says it does not")
		}
		if vc, ok := entry.Policy().EvaluateAttrString("ValidCommands"); !ok || vc != "74000" {
			t.Errorf("ValidCommands = %q (ok=%v), want it still advertised", vc, ok)
		}
	})
}

// AuthorizationLimitsPermit is what sessionSatisfies calls, so check the minted
// set actually refuses a level outside it and admits one inside.
func TestMintedLimitsRefuseLevelsOutsideTheSet(t *testing.T) {
	GetSessionCache().Clear()
	sid, _, err := MintInheritableSessionWithLimits("<127.0.0.1:9999>", []string{"READ"}, 74000)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	entry, ok := GetSessionCache().LookupNonExpired(sid)
	if !ok {
		t.Fatal("minted session missing")
	}
	raw, _ := entry.Policy().EvaluateAttrString(AttrLimitAuthorization)
	limits := parseLimitAuthorization(raw)

	if !AuthorizationLimitsPermit(limits, []string{"READ"}) {
		t.Error("READ was refused by a READ bounding set")
	}
	if AuthorizationLimitsPermit(limits, []string{"ADMINISTRATOR"}) {
		t.Error("ADMINISTRATOR was permitted by a READ bounding set")
	}
}
