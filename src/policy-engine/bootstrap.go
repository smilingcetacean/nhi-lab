package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// loadBootstrapParents reads the read-only ConfigMap-mounted table of root
// parents: spiffe_id -> the scopes they hold. Root
// parents have no grant module in OPA (they were never vended as a child), so
// this file is the base case of Π(P) derivation. It is cluster-provisioned at
// deploy time, not runtime-writable, which is what keeps it from
// reintroducing the asserted-Π(P) problem the wire protocol deliberately
// avoids.
//
// A missing file is not an error: it means no root parents are configured,
// so every unknown parent's Π(P) is the empty set from the bootstrap side —
// consistent with the fail-closed default. An empty JSON object behaves
// identically. A file that exists but is not valid JSON IS an error: that is
// a deployment mistake, not an absence of configuration, and should fail
// loudly at startup rather than silently grant nobody anything while looking
// like it started fine.
func loadBootstrapParents(path string) (map[string][]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, fmt.Errorf("read bootstrap parents file %s: %w", path, err)
	}
	var table map[string][]string
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("parse bootstrap parents file %s: %w", path, err)
	}
	if table == nil {
		table = map[string][]string{}
	}
	return table, nil
}
