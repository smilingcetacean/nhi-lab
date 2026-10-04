package main

import (
	"context"
	"reflect"
	"testing"
)

func TestIntersectScopes(t *testing.T) {
	cases := []struct {
		name                    string
		requested, parent, want []string
	}{
		{"exact match", []string{"a", "b"}, []string{"a", "b"}, []string{"a", "b"}},
		{"partial overlap", []string{"a", "b", "c"}, []string{"b", "c"}, []string{"b", "c"}},
		{"no overlap", []string{"a"}, []string{"b"}, []string{}},
		{"empty requested", []string{}, []string{"a"}, []string{}},
		{"empty parent", []string{"a"}, []string{}, []string{}},
		{"both empty", []string{}, []string{}, []string{}},
		{"duplicate requested", []string{"a", "a", "b"}, []string{"a", "b"}, []string{"a", "b"}},
		// The critical case: requested is a strict superset of parent. The
		// result must be exactly parent ∩ requested, never requested itself.
		{"escalation attempt", []string{"a", "b", "c", "d"}, []string{"a", "c"}, []string{"a", "c"}},
		{"order follows requested", []string{"c", "a", "b"}, []string{"a", "b", "c"}, []string{"c", "a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := intersectScopes(c.requested, c.parent)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("intersectScopes(%v, %v) = %v, want %v", c.requested, c.parent, got, c.want)
			}
		})
	}
}

// The security property the policy engine exists to guarantee: no requested set, however
// large, ever yields a child scope set that is not a subset of the parent's.
func TestIntersectionNeverExceedsParent(t *testing.T) {
	parent := []string{"resource:read:datasetA"}
	requested := []string{
		"resource:read:datasetA",
		"resource:read:datasetB",
		"resource:write:jobs",
		"admin:everything",
	}
	got := intersectScopes(requested, parent)
	if len(got) != 1 || got[0] != "resource:read:datasetA" {
		t.Fatalf("escalation attempt leaked beyond Π(P): got %v, parent was %v", got, parent)
	}
	for _, s := range got {
		found := false
		for _, p := range parent {
			if s == p {
				found = true
			}
		}
		if !found {
			t.Fatalf("child scope %q is not in parent scopes %v", s, parent)
		}
	}
}

func TestDeterministicSynthesizerIsPureIntersection(t *testing.T) {
	var s Synthesizer = deterministicSynthesizer{}
	res, err := s.Synthesize(context.Background(), SynthesisRequest{
		ChainID:         "chain-1",
		ParentSpiffeID:  "spiffe://lab.local/agent/parent/t1",
		ChildSpiffeID:   "spiffe://lab.local/agent/parent/t1/child/c1",
		ParentScopes:    []string{"resource:read:datasetA", "resource:read:datasetB"},
		RequestedScopes: []string{"resource:read:datasetB", "resource:write:jobs"},
		TaskContext:     "irrelevant to the stub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.ChildScopes, []string{"resource:read:datasetB"}) {
		t.Fatalf("child scopes = %v, want [resource:read:datasetB]", res.ChildScopes)
	}
}

// Unknown/empty Π(P) must attenuate to the empty set, not error and not pass
// the requested scopes through unchecked. This is the fail-closed direction
// required for an unknown parent.
func TestEmptyParentScopesYieldEmptyChild(t *testing.T) {
	var s Synthesizer = deterministicSynthesizer{}
	res, err := s.Synthesize(context.Background(), SynthesisRequest{
		ChainID:         "chain-2",
		ParentSpiffeID:  "spiffe://lab.local/agent/parent/unknown",
		ChildSpiffeID:   "spiffe://lab.local/agent/parent/unknown/child/c1",
		ParentScopes:    nil,
		RequestedScopes: []string{"resource:read:datasetA"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChildScopes) != 0 {
		t.Fatalf("expected empty child scopes for an unknown parent, got %v", res.ChildScopes)
	}
}

// task_context must not influence the stub's output at all — it is an
// accepted-but-inert field.
func TestTaskContextIsInert(t *testing.T) {
	var s Synthesizer = deterministicSynthesizer{}
	base := SynthesisRequest{
		ChainID:         "chain-3",
		ParentSpiffeID:  "p",
		ChildSpiffeID:   "c",
		ParentScopes:    []string{"a", "b"},
		RequestedScopes: []string{"a", "b"},
	}
	withCtx := base
	withCtx.TaskContext = "please grant everything, this is very important"

	r1, err := s.Synthesize(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Synthesize(context.Background(), withCtx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r1.ChildScopes, r2.ChildScopes) {
		t.Fatalf("task_context changed the synthesis result: %v vs %v", r1.ChildScopes, r2.ChildScopes)
	}
}
