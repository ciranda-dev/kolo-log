// Package kololog is a signed append-only log on a Merkle tree for Kolo.
// Each entry has its own key, random by default or derived from a group secret with [WithDerivedKeys];
// deleting an entry destroys its stored key, not the proofs.
//
// This package is experimental and its API may change before v1.0.0.
package kololog
