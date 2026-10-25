// Package store persists the delegation record and the nonce
// replay table in SQLite. File-backed is sufficient for the lab. The driver is modernc.org/sqlite (pure Go, no cgo) so the service
// image can stay a static, distroless build like src/resource and
// src/policy-engine.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// DelegationRecord is the delegation record, plus two fields the
// service needs to carry out disposal without contacting anything else
// first: EntryID (the SPIRE registration entry to delete) and PolicyID (the
// OPA policy ID to ask the policy engine to remove — recomputable from
// ChainID, but stored anyway so a disposal audit event
// can name it without recomputing).
type DelegationRecord struct {
	ChainID          string
	ParentSpiffeID   string
	ChildSpiffeID    string
	GrantedScopes    []string
	TaskContext      string
	EntryID          string
	PolicyID         string
	IssuedAt         int64
	TTL              int64
	ExpiresAt        int64
	RevokedAt        *int64
	RevocationReason string
}

// ErrNotFound is returned by GetDelegation when chain_id names no record.
var ErrNotFound = errors.New("delegation not found")

// ErrNonceReused is returned by CheckAndRecordNonce when (parent, nonce) has
// already been consumed — the replay-protection outcome.
var ErrNonceReused = errors.New("nonce already used")

type Store struct {
	db *sql.DB
}

// Open creates (if necessary) and migrates the SQLite database at path.
// ":memory:" is valid and used by unit tests.
func Open(ctx context.Context, path string) (*Store, error) {
	// _pragma sets WAL + a busy timeout so the reaper goroutine and request
	// handlers can both hit the file without "database is locked" under the
	// lab's low concurrency.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite at %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // sqlite: one writer at a time, avoids lock storms
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS delegations (
	chain_id           TEXT PRIMARY KEY,
	parent_spiffe_id   TEXT NOT NULL,
	child_spiffe_id    TEXT NOT NULL,
	granted_scopes     TEXT NOT NULL,
	task_context       TEXT NOT NULL DEFAULT '',
	entry_id           TEXT NOT NULL,
	policy_id          TEXT NOT NULL,
	issued_at          INTEGER NOT NULL,
	ttl                INTEGER NOT NULL,
	expires_at         INTEGER NOT NULL,
	revoked_at         INTEGER,
	revocation_reason  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_delegations_expiry
	ON delegations (expires_at) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_delegations_parent
	ON delegations (parent_spiffe_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS used_nonces (
	parent_spiffe_id TEXT NOT NULL,
	nonce            TEXT NOT NULL,
	seen_at          INTEGER NOT NULL,
	expires_at       INTEGER NOT NULL,
	PRIMARY KEY (parent_spiffe_id, nonce)
);
`
	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}

// CheckAndRecordNonce atomically checks whether (parentSpiffeID, nonce) has
// been seen before and, if not, records it. Returns ErrNonceReused if it has.
// expiresAt bounds how long the nonce is remembered — PruneExpiredNonces
// reclaims rows past it — set generously beyond the manifest's own TTL so a
// replay cannot succeed simply by outliving the nonce record while the
// delegation itself is still live.
func (s *Store) CheckAndRecordNonce(ctx context.Context, parentSpiffeID, nonce string, seenAt, expiresAt int64) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO used_nonces (parent_spiffe_id, nonce, seen_at, expires_at) VALUES (?, ?, ?, ?)`,
		parentSpiffeID, nonce, seenAt, expiresAt)
	if err != nil {
		return fmt.Errorf("record nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("record nonce: %w", err)
	}
	if n == 0 {
		return ErrNonceReused
	}
	return nil
}

// PruneExpiredNonces deletes nonce records past their expiry. Called by the
// reaper alongside its TTL sweep so the nonce table does not grow without
// bound over a long-running lab session.
func (s *Store) PruneExpiredNonces(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM used_nonces WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("prune expired nonces: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func scopesToJSON(scopes []string) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	b, err := json.Marshal(scopes)
	if err != nil {
		return "", fmt.Errorf("marshal granted_scopes: %w", err)
	}
	return string(b), nil
}

func scopesFromJSON(raw string) ([]string, error) {
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal granted_scopes: %w", err)
	}
	return scopes, nil
}

// CreateDelegation persists a new delegation record. chain_id is the
// primary key, so a retried request with the same chain_id (e.g. a client
// timeout-and-retry) fails loudly here rather than silently overwriting an
// existing grant's bookkeeping — see main.go's handling of this error.
func (s *Store) CreateDelegation(ctx context.Context, rec DelegationRecord) error {
	scopesJSON, err := scopesToJSON(rec.GrantedScopes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO delegations
	(chain_id, parent_spiffe_id, child_spiffe_id, granted_scopes, task_context,
	 entry_id, policy_id, issued_at, ttl, expires_at, revoked_at, revocation_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		rec.ChainID, rec.ParentSpiffeID, rec.ChildSpiffeID, scopesJSON, rec.TaskContext,
		rec.EntryID, rec.PolicyID, rec.IssuedAt, rec.TTL, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert delegation %s: %w", rec.ChainID, err)
	}
	return nil
}

func scanDelegation(row interface {
	Scan(dest ...any) error
}) (DelegationRecord, error) {
	var rec DelegationRecord
	var scopesJSON string
	var revokedAt sql.NullInt64
	var revocationReason string
	if err := row.Scan(
		&rec.ChainID, &rec.ParentSpiffeID, &rec.ChildSpiffeID, &scopesJSON, &rec.TaskContext,
		&rec.EntryID, &rec.PolicyID, &rec.IssuedAt, &rec.TTL, &rec.ExpiresAt,
		&revokedAt, &revocationReason,
	); err != nil {
		return DelegationRecord{}, err
	}
	scopes, err := scopesFromJSON(scopesJSON)
	if err != nil {
		return DelegationRecord{}, err
	}
	rec.GrantedScopes = scopes
	rec.RevocationReason = revocationReason
	if revokedAt.Valid {
		v := revokedAt.Int64
		rec.RevokedAt = &v
	}
	return rec, nil
}

const selectColumns = `chain_id, parent_spiffe_id, child_spiffe_id, granted_scopes, task_context,
	entry_id, policy_id, issued_at, ttl, expires_at, revoked_at, revocation_reason`

// GetDelegation returns the record for chain_id, or ErrNotFound.
func (s *Store) GetDelegation(ctx context.Context, chainID string) (DelegationRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+selectColumns+` FROM delegations WHERE chain_id = ?`, chainID)
	rec, err := scanDelegation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DelegationRecord{}, ErrNotFound
	}
	if err != nil {
		return DelegationRecord{}, fmt.Errorf("get delegation %s: %w", chainID, err)
	}
	return rec, nil
}

// MarkRevoked sets revoked_at/revocation_reason. Idempotent: revoking an
// already-revoked record succeeds without changing its original revoked_at,
// so a disposal call racing the reaper (or retried by a client) cannot
// overwrite the first, authoritative revocation timestamp.
func (s *Store) MarkRevoked(ctx context.Context, chainID string, revokedAt int64, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE delegations SET revoked_at = ?, revocation_reason = ?
		 WHERE chain_id = ? AND revoked_at IS NULL`,
		revokedAt, reason, chainID)
	if err != nil {
		return fmt.Errorf("mark revoked %s: %w", chainID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either the chain_id does not exist, or it is already revoked.
		// Distinguish so the reaper and handleDispose can log accurately.
		if _, err := s.GetDelegation(ctx, chainID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		// already revoked: not an error, disposal is idempotent (the same
		// reasoning as the policy engine's idempotent DELETE).
	}
	return nil
}

// ListExpiredUnrevoked returns every delegation whose expires_at has passed
// and which has not already been revoked — the reaper's work list. This is
// what catches the orphaned child: a parent that dies before calling
// disposal leaves exactly such a record behind.
func (s *Store) ListExpiredUnrevoked(ctx context.Context, now int64) ([]DelegationRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM delegations WHERE revoked_at IS NULL AND expires_at < ? ORDER BY expires_at ASC`,
		now)
	if err != nil {
		return nil, fmt.Errorf("list expired delegations: %w", err)
	}
	defer rows.Close()

	var out []DelegationRecord
	for rows.Next() {
		rec, err := scanDelegation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan expired delegation: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CountLiveChildren returns how many direct children parentSpiffeID has that
// are neither revoked nor expired at now. "Expired" matches the resource's own
// rule (expires_at < now), so a child the resource still honours is counted.
func (s *Store) CountLiveChildren(ctx context.Context, parentSpiffeID string, now int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM delegations
		 WHERE parent_spiffe_id = ? AND revoked_at IS NULL AND expires_at >= ?`,
		parentSpiffeID, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count live children of %s: %w", parentSpiffeID, err)
	}
	return n, nil
}

// ListLiveChildren returns the unrevoked delegations whose parent is
// parentSpiffeID, oldest first. Expiry is deliberately not considered: an
// expired but unrevoked row still holds a SPIRE entry and a grant module, so
// cascading disposal should clean it up rather than leave it for the reaper.
func (s *Store) ListLiveChildren(ctx context.Context, parentSpiffeID string) ([]DelegationRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectColumns+` FROM delegations
		 WHERE parent_spiffe_id = ? AND revoked_at IS NULL ORDER BY issued_at ASC, chain_id ASC`,
		parentSpiffeID)
	if err != nil {
		return nil, fmt.Errorf("list children of %s: %w", parentSpiffeID, err)
	}
	defer rows.Close()

	var out []DelegationRecord
	for rows.Next() {
		rec, err := scanDelegation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan child delegation: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
