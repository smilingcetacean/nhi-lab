package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// chainIDPattern is the accepted shape for chain_id. slugify
// lowercases and maps every character outside [a-z0-9_] to '_', so a wider
// accepted set — e.g. one that still allowed uppercase or '-' — would let
// distinct inputs like "chain-1", "chain_1" and "CHAIN-1" collide onto the
// same policy_id and silently overwrite each other's grant module. Accepting
// ONLY [a-z0-9_] here makes slugify the identity function over every value
// that reaches it: nothing chainIDPattern accepts is changed by
// lowercasing (there is nothing left to lowercase) or by the '-'→'_'
// substitution (there is no '-' left to substitute). Two distinct accepted
// chain_ids are therefore always two distinct policy IDs — genuinely
// injective, not merely "less likely to collide". See TestValidateChainID*
// and TestAcceptedChainIDsRemainDistinctAfterSlugify.
var chainIDPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

func validateChainID(chainID string) error {
	if !chainIDPattern.MatchString(chainID) {
		return fmt.Errorf("chain_id %q must match %s", chainID, chainIDPattern.String())
	}
	return nil
}

// validateChildDescendant checks the child/parent relationship.
// child_spiffe_id is caller asserted, so it must be validated as actually a
// descendant of parent_spiffe_id. Left unchecked, two legal-looking /synthesize calls
// compose into privilege escalation: synthesize(parent=P1, child=P2,
// requested=A) legally writes a grant naming P2 (since Π(C)={A}⊆Π(P1)), and
// P2 is a wholly unrelated identity — nothing says P2 is P1's child. A
// subsequent synthesize(parent=P2, ...) then reads back that grant as P2's
// OWN authority via deriveParentScopes, which unions every grant module
// naming the parent regardless of how it came to exist.
//
// Under the lab's SPIFFE ID scheme, a legitimate child of parent P is exactly
// P + "/child/" + <subtask-id>, with a non-empty, single-segment
// <subtask-id>. Enforcing that here closes the composition: a grant can only
// ever name an identity that is structurally subordinate to the parent it was
// synthesized against, so deriveParentScopes can no longer be fed authority
// that was never actually delegated to that parent.
//
// A child_spiffe_id that already appears in the bootstrap root-parent table
// is also rejected: a root parent is pre-provisioned, cluster-declared
// authority and cannot legitimately be the target of a
// synthesized (i.e. caller-triggered) grant.
func validateChildDescendant(parentSpiffeID, childSpiffeID string, bootstrap map[string][]string) error {
	parentID, err := spiffeid.FromString(parentSpiffeID)
	if err != nil {
		return fmt.Errorf("parent_spiffe_id is not a valid SPIFFE ID: %w", err)
	}
	childID, err := spiffeid.FromString(childSpiffeID)
	if err != nil {
		return fmt.Errorf("child_spiffe_id is not a valid SPIFFE ID: %w", err)
	}
	if childID.TrustDomain() != parentID.TrustDomain() {
		return fmt.Errorf("child_spiffe_id %q is not in the same trust domain as parent_spiffe_id %q",
			childSpiffeID, parentSpiffeID)
	}

	const sep = "/child/"
	prefix := parentID.Path() + sep
	childPath := childID.Path()
	if !strings.HasPrefix(childPath, prefix) {
		return fmt.Errorf(
			"child_spiffe_id %q is not a descendant of parent_spiffe_id %q (expected path prefix %q)",
			childSpiffeID, parentSpiffeID, prefix)
	}

	subtask := childPath[len(prefix):]
	if subtask == "" {
		return fmt.Errorf("child_spiffe_id %q has an empty subtask-id after %q", childSpiffeID, sep)
	}
	if strings.Contains(subtask, "/") {
		return fmt.Errorf(
			"child_spiffe_id %q has more than one path segment after %q; only a direct child is a legitimate descendant here",
			childSpiffeID, sep)
	}
	if err := spiffeid.ValidatePathSegment(subtask); err != nil {
		return fmt.Errorf("child_spiffe_id %q has an invalid subtask-id segment %q: %w", childSpiffeID, subtask, err)
	}

	if _, isRootParent := bootstrap[childID.String()]; isRootParent {
		return fmt.Errorf(
			"child_spiffe_id %q is a bootstrap root parent and cannot legitimately be a synthesized child",
			childSpiffeID)
	}

	return nil
}
