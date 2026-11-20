# kolo-log

Signed append-only log with deletion for Kolo.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

A log that strangers can check and its owner can still delete from. Entries sit on a Merkle tree hashed and proved as in [Certificate Transparency 2.0 (RFC 9162)](https://www.rfc-editor.org/info/rfc9162), with [BLAKE2b-256 (RFC 7693)](https://www.rfc-editor.org/info/rfc7693) in place of SHA-256, and every record and head is signed with [Ed25519ctx (RFC 8032)](https://www.rfc-editor.org/info/rfc8032), so any peer can verify that an entry is in the log and that the log only grew. Each entry is encrypted under its own key, and deleting an entry destroys that key while every proof stays valid, as [Boneh and Lipton](https://www.usenix.org/conference/6th-usenix-security-symposium/revocable-backup-system) proposed.

Identities come from [kolo-id](https://github.com/ciranda-dev/kolo-id) and encodings from [kolo-codec](https://github.com/ciranda-dev/kolo-codec). A log has one writer. A peer that follows someone else's log holds a read-only `Replica` that verifies every head, entry and proof before it moves forward. kolo-log is pure Go with no cgo and nothing to install, and it keeps entries in a `Storage` you provide: `NewMemory()` for tests, or [kolo-store](https://github.com/ciranda-dev/kolo-store) for disk.

## Install

```sh
go get github.com/ciranda-dev/kolo-log
```

## Quick start

Create a log, append an entry, check it against the signed head with an inclusion proof, then delete it. Save it outside the repository and run it with `go run .` in a module that requires kolo-log and kolo-id.

```go
package main

import (
	"errors"
	"fmt"
	"log"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
)

func main() {
	me, err := koloid.Generate()
	check(err)
	l, err := kololog.New(me, kololog.NewMemory(), kololog.WithValueEncoding(kololog.UTF8))
	check(err)
	i, err := l.Append("hello")
	check(err)

	h, err := l.Head()
	check(err)
	head, err := kololog.VerifyHead(me.PublicKey(), l.ID(), h)
	check(err)
	rec, err := l.Record(i)
	check(err)
	proof, err := l.InclusionProof(i, head.Size())
	check(err)
	fmt.Println(kololog.VerifyInclusion(head, rec, proof))

	check(l.Delete(i))
	var s string
	fmt.Println(errors.Is(l.Read(i, &s), kololog.ErrDeleted))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
```

```text
$ go run .
true
true
```

A reader needs two things it already trusts: the owner's public key and the log ID it expects. Everything else (heads, records, proofs) can come from any peer.

## API

| Symbol | What it does |
|---|---|
| `New(id, s, opts...)` | Create a log with a random log ID that keeps its entries in `s`. `WithValueEncoding` picks `Bytes` (the default), `UTF8` or `JSON` |
| `Append(v)` | Add an entry and commit it with a new signed head in one write |
| `Read(i, &out)`, `Get(i)` | Decode an entry, or return its stored bytes |
| `Delete(indexes...)` | Sign a delete marker for each entry and destroy its key; reads then return `ErrDeleted` and every proof still verifies |
| `Head()`, `Record(i)` | The signed head and the signed record of an entry |
| `InclusionProof`, `ConsistencyProof` | What a reader needs to check an entry, or that the log only grew |
| `VerifyHead`, `VerifyRecord`, `VerifyInclusion`, `VerifyConsistency` | Check what a peer sent. `VerifyHead` returns the `VerifiedHead` the other two accept |
| `VerifyDeleteMarker`, `VerifyLogHeader` | Check a delete marker and the signed log header |
| `Restore(id, header, head, s, opts...)` | Rebuild a writable log from storage, verifying all of it |
| `NewReplica`, `RestoreReplica` | A read-only copy of someone else's log. `Update`, `AddKey` and `ApplyDelete` are the only ways it changes |
| `OpenEntry(h, proof, e)` | Check an entry fetched on its own against a verified head |
| `WithDerivedKeys(&secret, epoch)` | Opt in, per log, to entry keys derived from a group secret, so any holder of the secret reads the log without the writer online |
| `NewKeyDeriver`, `Replica.AddKeys` | Derive the keys of a log with derived keys, and give a replica many keys in one write |
| `Storage` | The interface a log keeps entries in: `Entry`, `Key` and `Commit` |

A `Log` is safe for concurrent use. Every `Decode` function and verifier takes untrusted bytes and returns an error or false, never a panic.

Deletion is best effort: it holds on every peer that follows the protocol and applies the delete marker, and a peer that already received the key can keep it. In a log with derived keys, anyone who holds the secret and kept a ciphertext can still read it after it is deleted.

Errors work with `errors.Is`, for example `ErrDeleted`, `ErrRollback`, `ErrDiverged`, `ErrBadProof`, `ErrBadEntry`, `ErrInvalidHead` and `ErrKeyUnavailable`. The full lists are in the guide.

## More

- [docs/guide.md](docs/guide.md): the log, replicas, entry keys, derived-key logs, storage, restore and checking one entry.
- [docs/formats.md](docs/formats.md): binary and JSON forms, signing contexts and references.
- [docs/limits.md](docs/limits.md): bounds, memory and caveats.
- [examples/basic](examples/basic/main.go): a runnable example.
- [SECURITY.md](SECURITY.md): security policy.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
