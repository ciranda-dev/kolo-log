# Guide

Walkthrough of the API. The binary and JSON forms are in [formats.md](formats.md) and the bounds in [limits.md](limits.md). A complete program is in the README, and [examples/basic](../examples/basic/main.go) is a runnable example.

## Writing and reading

A `Log` has one writer and is safe for concurrent use.

- `New(id, s, opts...)` creates a log with a random 32-byte log ID that
  keeps its entries in `s`, a `Storage` (see Storage below; `NewMemory()`
  for a log that is not persisted). `WithValueEncoding` picks how values
  are stored: `Bytes` (the default, takes `[]byte`), `UTF8` (takes a valid
  UTF-8 `string`) or `JSON` (takes any value, stored as `json.Marshal(v)`).
- `Append(v)` adds an entry, commits it with a head signed right after it
  in one `Storage.Commit`, and returns its index. `Read(i, &out)` decodes it
  into `*[]byte`, `*string` or, for JSON, any non-nil pointer. `Get(i)`
  returns the stored bytes. A value or output of the wrong type returns
  `ErrWrongValueType`, invalid UTF-8 returns `ErrInvalidUTF8`, and an entry
  over about 254 GiB (about 512 MiB on 32-bit platforms) returns
  `ErrEntryTooLarge`. JSON errors name only Go types, never values. With
  JSON, `encoding/json` keeps its own internal buffers, which kolo-log
  cannot clear.
- `Delete(indexes...)` signs a delete marker with the log key for each
  entry and commits them all in place of the entries' ciphertexts and keys
  in one `Storage.Commit`, so deleting many entries costs one durable write
  plus one signature each (on kolo-store with Pebble, 1,000 entries take
  about 34 ms in one call against about 3.6 s one at a time). An index out
  of range deletes nothing; entries already deleted are skipped. Reads then
  return `ErrDeleted`, while the head, the record and every proof still
  verify.
  `VerifyDeleteMarker(pub, logID, r, m)` checks a marker against its
  record. Deletion is best effort: it holds on every peer that follows the
  protocol and applies the marker, and a peer that already received the
  key can keep it.
- `Entry(i)` returns the stored form of an entry (record, ciphertext or
  marker, key) for a sync layer. `Key(i)` returns only the key and
  `EntryInfo(i)` whether the entry is deleted and whether its key is
  stored, so a sync layer can list markers and keys without reading
  ciphertexts.
- `Head()` signs and returns the current head. `Record(i)`,
  `InclusionProof(i, size)` and `ConsistencyProof(old, new)` return what a
  reader needs to check an entry or that the log only grew.
- `VerifyHead(pub, logID, h)` checks a head and returns a `VerifiedHead`,
  the only value `VerifyInclusion` and `VerifyConsistency` accept. Passing a
  plain `Head` does not compile, and a zero `VerifiedHead{}` never verifies.
  The error wraps `ErrInvalidHead`, and `ErrWrongLogID` tells a head of
  another log from a bad signature (`ErrBadHeadSignature`).
- `VerifyRecord(pub, logID, r)` checks one record on its own.
- `Header()` returns the signed `LogHeader` (author key, log ID, value
  encoding). `VerifyLogHeader(pub, h)` checks it.
- Only one writable log per (author key, log ID) can be open in a process:
  `New` and `Restore` return `ErrLogOpen` otherwise. `Close()` releases it;
  after that `Append`, `Head` and `Delete` return
  `ErrLogClosed`, while reads keep working. `Reserve(logKey, logID)`
  holds that pair (for example while storage deletes the log): it fails
  with `ErrLogOpen` if a writable log with that key and ID is open or the
  pair is reserved, and until `release` is called `New` and `Restore` of
  that pair return `ErrLogOpen`. `ReserveForRestore(logKey, logID)` does
  the same and returns an option that lets one `Restore` of exactly that
  key and ID take the reservation over, so a storage layer can hold it
  from before it loads data until the log is open. Open logs,
  reservations and takeovers all use the same (log key, log ID) pair.
  `ReserveID(logID)` reserves an ID under every key, for storage that
  cannot trust which key a log belongs to (for example a missing or
  corrupt header).

Every `Decode` function and verifier takes untrusted bytes and returns an
error or false, never a panic.

## Replicas

A `Replica` is a read-only copy of someone else's log. It needs only the
owner's public key, the log ID and the signed log header, never a private
key. It works like a monitor in RFC 9162, section 8.2: it keeps a verified
head and every entry, and only moves forward.

- `NewReplica(pub, logID, header, s)` starts an empty replica that keeps
  its entries in `s`. `RestoreReplica(pub, logID, header, heads, s)`
  rebuilds a persisted one and verifies all of it, like `Restore`: it reads
  the entries of `heads.Head` from `s`, then replays a pending
  `heads.Target` through the checks of `Update`, reading the entries up to
  `heads.Proof.OldSize`. Zero `Heads` are a replica that has not grown yet.
  The replica commits its heads with every change, so the storage always
  holds what `RestoreReplica` needs.
- `Update(h, proof, entries)` is the only way to grow. It verifies `h`
  (signature, context, log ID), then each entry from `Len()` on: the record
  signature and index, the ciphertext size and hash against the record or a
  valid delete marker in its place, and that the key, when given, matches
  the record's key commitment and opens the ciphertext. The entries may
  stop at any size `m` up to `h.Size`, so a replica far behind catches up
  in chunks and never holds the whole missing range at once. `proof` is the
  consistency proof from `m` to `h.Size`, checked against the root the
  replica rebuilds from every leaf it holds, as RFC 9162 monitors check
  fetched entries against a signed head; when the entries reach `h.Size`,
  it may also be the proof from `Len()` (an empty replica needs none), and
  the rebuilt root must equal the root of `h`. `Update` copies the entries
  before it checks them and commits exactly those copies with the new
  heads in one `Storage.Commit`. On any error, a failed commit included,
  the replica stays exactly as it was.
- While a chunk stops short of `h`, `Target()` returns `h` and the proof
  that the first `Len()` entries are a prefix of it; the replica commits
  both, and `RestoreReplica` replays them after a restart. `Head()`
  stays the last head whose every entry the replica holds, and `Len()`
  counts every verified entry, also those past `Head()`. While a target is
  pending, a head between `Len()` and the target's size is refused
  unchecked with `ErrRollback`, which there does not mean the head shares
  the replica's history; a chunk toward a larger head must reach the
  target's size, and the root rebuilt at the target's size must equal the
  target's root (`ErrDiverged` otherwise), so the replica never drops a
  signed target without checking it against the next head. A held head
  never clears the target. A chunk may also be empty: a newer head with the
  proof from `Len()` becomes the target without new entries.
- Errors from `Update`, for `errors.Is`: `ErrInvalidHead` (with
  `ErrBadHeadSignature` or `ErrWrongLogID`), `ErrRollback` (an older head
  of the same history), `ErrDiverged` (a head whose root differs from the
  held entries at its size, or from the head or target of its size: the
  owner signed two histories), `ErrBadProof`, `ErrBadEntry` and
  `ErrLogClosed`. A head whose entries the replica already holds becomes
  its head if it is newer, and otherwise does nothing.
- An entry may come without its key and then reads as `ErrKeyUnavailable`.
  `AddKey(i, key)` gives it the key later, after the same commitment and
  decryption checks against the ciphertext read from storage, and commits
  it; a deleted entry returns `ErrDeleted`, and another key for an entry
  that has one returns `ErrBadEntry`.
- `ApplyDelete(markers...)` verifies encoded delete markers against the
  records the replica holds, then commits them in place of those entries'
  ciphertexts and keys in one `Storage.Commit`. One bad marker applies
  none. Reads then return `ErrDeleted`. A marker already applied is
  skipped. As with `Delete`, deletion is best effort: it holds on
  peers that follow the protocol, and a peer that already received the key
  can keep it.
- Reads work like the writer's: `Len`, `Head` (the last verified head,
  exactly as received, or `ErrNoHead`), `Record`, `Entry`, `Key`,
  `EntryInfo`, `Get`, `Read`, `InclusionProof`, `ConsistencyProof`,
  `Header`, `ID`. `Close` stops
  `Update`, `AddKey` and `ApplyDelete`. There is no `Append` and no delete by index.

Multi-device use and chat use one log per device or person, each
replicated by the others as a read-only replica. There is no multi-writer
log.

## Entry keys

`Entry.Key` is the entry's key (an `EntryKey`), nil when it is unknown or
the entry is deleted. `Entry(i)` fills it and `Key(i)` returns it alone, so
a sync layer can hand it, with the verified entry, to a replica. `encoding/json` leaves `Entry.Key` out.
`fmt` and `slog` show an `EntryKey` as `[redacted]` when it is passed on
its own or reached through exported fields; inside an unexported struct
field, `fmt` and `slog.Any` print the raw bytes, and an encoder that
ignores `MarshalJSON` (such as `encoding/gob`) writes the key in clear.
The caller owns the copy it gets and should clear it when done.

Each record carries `KeyCommit`, the BLAKE2b-256 hash of the string
`kolo-log/key/v0` and the entry key (in kolo-codec form). XChaCha20-Poly1305
is not key-committing, so without it the owner could craft one ciphertext
that opens under two keys to two plaintexts and show different readers
different content under one signed record. `Restore`, `RestoreReplica`,
`Update`, `AddKey` and `AddKeys` check a key against the commitment before
decrypting with it.

## Derived-key logs

A log has one of two key modes, fixed in its signed header:

- `RandomKeys`, the default: every entry gets a fresh random key that only
  the writer holds. A reader gets keys from the writer, so the writer can
  give keys to some readers and only ciphertext to others, and `Delete`
  destroys the only key.
- `DerivedKeys`, with `New(id, s, WithDerivedKeys(&secret, epoch))`: every
  entry key is derived from a group secret, the log and the entry's index.
  Anyone who holds the secret derives the key of any entry and opens the
  ciphertext it got from the writer, a replica or a pin, without the writer
  online. No key has to travel.

Use `DerivedKeys` only when every holder of the secret may read every entry
of the log. A log that withholds keys from some readers keeps `RandomKeys`.

The derivation is HKDF-SHA256 (RFC 5869, Go's `crypto/hkdf`). Extract runs
once per log with an empty salt (RFC 5869 2.2: 32 zero bytes), and Expand
once per entry:

```text
PRK = HKDF-Extract(salt = empty, IKM = secret)
key = HKDF-Expand(PRK, info, 32)
info = string "kolo-log/entry-key/v0" | fixed[32] log key | fixed[32] log ID | uvarint epoch | uvarint index
```

`info` is in kolo-codec form: the string is length-prefixed and the
uvarints minimal, so two inputs never give the same `info`. The derived key
goes through the same paths as a random one: XChaCha20-Poly1305 with a fresh
random 24-byte nonce per seal, the same associated data, the same
`KeyCommit`, and the writer stores it with the entry, so `Get`, `Key` and
`Entry` work as with random keys. An index sealed twice (the next `Append`
after a failed commit, a log restored from an older copy, or one data
directory copied to two devices) reuses its key under another random nonce.

The `EntrySecret` must be 32 uniformly random bytes, from `crypto/rand`.
Extract is kept for the standard two-step form, not to rescue a weak
secret: in this mode every record's `KeyCommit` is a public function of the
secret, so with a guessable secret anyone holding one record can find it
offline. Use the secret for nothing else: a key that also keys something
else (a group's conversation key, for example) must not be passed as the
secret; derive the secret from it first with HKDF under its own label.
`WithDerivedKeys` copies the secret when it is called; that copy lives as
long as the `Option`.

The epoch is set by the caller and is in the signed header and in `info`.
A new secret goes with new logs at the next epoch, and a log never mixes
epochs. `Restore` returns `ErrKeyModeMismatch` when the header and the
options disagree on the mode or the epoch, and `ErrSecretMismatch` when the
secret does not derive the key the newest record commits to (also after
that entry was deleted). An empty log has no record to check the secret
against, so `Restore` accepts any secret for it.

kolo-log never compares epochs across logs. An application that moves its
readers to a new epoch must itself refuse a header whose epoch is below the
one it now uses, and must not show entries appended to an old-epoch log
after the move as new: every holder of the old secret, a removed reader
included, can read them.

A reader that holds the secret makes a `KeyDeriver` with
`NewKeyDeriver(secret, owner, header)`: it checks the header with
`VerifyLogHeader(owner, header)` and returns `ErrNotDerived` for a header
with random keys. `Key(i)` derives the key of entry `i`, and `Close` clears
the deriver's copy of the PRK, after which `Key` returns
`ErrDeriverClosed`. A `KeyDeriver` is safe for concurrent use.

`Replica.AddKeys(start, keys)` gives a replica the keys of many entries at
once: it checks every key once against the entries from `start` on and
stores every key that passes in one `Storage.Commit`. A nil key skips its
entry, and so does an entry that is deleted or already keyed. A key the
signed record proves wrong (the record does not commit to it, or the
ciphertext the record signs does not open under it) is refused; all refused
indexes come back together, in ascending order, in one `*BadKeyError`,
which wraps `ErrBadEntry`, and the keys that passed are stored anyway. A key
that fails its commitment is refused without reading or decrypting
anything. A storage error or `ErrStorageMismatch` stores and refuses
nothing: call `AddKeys` again later, for example after the next pull. One
call takes at most `MaxAddKeys` (32,768) keys, as many entries as one
kolo-sync answer can carry, and more returns `ErrTooManyKeys`. Each key
costs one commitment hash and at most one storage read and one decryption.
`AddKeys` takes the replica's lock for each storage read (shared) and for
the final commit, never across the decryptions, so other calls on the
replica run in between. A refused
index is a fact the writer signed, so it never needs a second look. A
reader that follows many writers should still cap how many refusals it
keeps per writer (for example 256, the most messages the chat example's
window holds) and stop deriving for a writer past that cap.

What the mode means for readers:

- **Who reads.** Everyone who ever held the secret reads every entry of the
  epoch whose ciphertext they can get, from the writer, a replica or any
  pin, without the writer online, for as long as copies are kept.
- **Removed reader.** kolo-log has no membership. A reader that held an
  epoch's secret keeps reading every entry of that epoch. Keeping it out of
  later entries takes a new secret from fresh random bytes, never derived
  from the old one, delivered only to the remaining readers, and new logs at
  the next epoch; it keeps every epoch it held and nothing after.
- **New reader.** Whoever gets the secret reads the whole history of the
  epoch, entries written before it got the secret included, also of
  writers it never meets.
- **Deletion does not revoke reading.** Deleting an entry cannot take it
  from anyone who holds the secret and kept a copy of its ciphertext: a key
  that can be derived again cannot be destroyed.
- **No forward secrecy within an epoch.** Whoever gets an epoch's secret,
  at any time, reads every entry of that epoch still on a pin or in a copy,
  past and future. Random keys let a writer destroy a key; derived keys give
  that up.

A pin or any other holder of ciphertext without the secret learns the mode
and the epoch of each log from its header, and reads nothing.

What prints key material, and what does not:

- `fmt` and `slog` show an `EntrySecret`, a `*EntrySecret` and a
  `*KeyDeriver` as `[redacted]`, and `encoding/json` writes an
  `EntrySecret` as `"[redacted]"`. A `KeyDeriver` value prints its log key,
  log ID and epoch, never the PRK.
- `fmt` and `slog` show a `*Log` and a `*Replica` as their log ID, value
  encoding, key mode and epoch, for every verb, so no verb prints the
  storage or the entry keys in it. The memory storage keeps each entry
  behind a pointer, so even a `*Log` reached through an unexported field
  prints addresses.
- The PRK lives only inside a closure. On fmt's bad-verb path (a verb a
  pointer cannot take, such as `%s` on a pointer in an unexported field)
  fmt prints the pointer's target and calls no method at all, so
  redaction methods cannot help there; neither that path nor a
  reflection-based dumper can enter a function. `Log.Close` and
  `KeyDeriver.Close` clear their copy of the PRK. HMAC keeps its own copies
  until the runtime reuses that memory.
- Printed raw, because fmt calls no method there: an `EntrySecret` inside an
  unexported struct field, by value or behind one pointer; `%p` of an
  `EntrySecret` value, or of a `KeyAt`, `Change` or `Entry` value, since fmt
  handles `%p` before `Format`; and, as for `EntryKey`, a key inside an
  unexported struct field.
- Encoders and dumpers that ignore these methods print or keep the bytes:
  `encoding/gob` round-trips an `EntrySecret` and an `EntryKey` in clear;
  dumpers that bypass methods and read unexported fields (go-spew with
  `DisableMethods`, as testify's diffs use it) print the secret and the entry
  keys a storage holds, though not the PRK; go-cmp's diff prints an
  `EntrySecret` as hex. Keep secrets out of such tools and of test failure
  messages.
- Every copy of an `EntrySecret` array is another copy of the secret.

## Storage

A log or replica keeps in memory only what proofs and checks need: the
tree hashes (about 64 bytes per entry) and a compact copy of each record
with two flags (144 bytes: size, content hash, key commitment,
signature, deleted, key stored). Ciphertexts, keys and markers live in its
`Storage`, an interface with three methods:

- `Entry(index) (Entry, error)` returns the stored form of an entry, or an
  error wrapping `ErrOutOfRange` for an index that holds none; any other
  error means the storage failed, and `New` and `NewReplica` return it.
  For an entry the log holds, that answer means the storage lost it: reads
  return `ErrStorageMismatch` and `Restore` `ErrRestoreMismatch`, never
  `ErrOutOfRange`.
- `Key(index) (EntryKey, error)` returns its key alone, nil if none.
- `Commit(Change) error` stores one change atomically and durably, or
  nothing. `Start` is always the log's length before the change. A
  `Change` holds new entries from index `Start` on, or the record and
  marker of each deleted entry (`Deleted`), or the key of an entry stored
  without one (`Key`) at `Index`, and the new `Heads` (head, and a
  replica's pending target and proof) when they change. `Commit` must copy
  what it keeps: the log zeroes the keys in the `Change` once it returns.

A storage belongs to one log: `New` and `NewReplica` return
`ErrStorageNotEmpty` for one that already holds an entry, and the memory
storage refuses entries that do not start at its length. `NewMemory()` is
the in-memory one; [kolo-store](https://github.com/ciranda-dev/kolo-store)
keeps logs on disk. Every change runs under the log's lock: the log checks
it, commits it, and only then shows it, so readers never see an entry that
is not stored, and a failed commit leaves the log exactly as it was, with no
special state to recover from. Memory grows with the number of entries,
never with their size.

Every read checks what storage returns against the record and flags in
memory: the record bytes, the ciphertext size and BLAKE2b-256 hash or a
valid delete marker, whether a marker and a key are stored, and the key
against the key commitment. A mismatch returns `ErrStorageMismatch`; an
error from the storage is returned wrapped. The hash is checked on every
read because the key is stored next to the ciphertext: data sealed again
under that key would otherwise open. `Get` and `Key` of a deleted entry
return `ErrDeleted` without reading storage, so an old value put back on
disk is never returned while the log is open.

`Restore(id, header, head, s, opts...)` rebuilds a writable log from its
header, its head and the entries in `s`, reading them one at a time, each
once and in increasing order, and verifying all of it: the header, the head,
every record and ciphertext hash, that each stored key opens its ciphertext,
that every live entry of an own log has its key, and the rebuilt tree root
against the head. It stops at the first mismatch and never repairs anything.
It checks the entries in parallel (up to `GOMAXPROCS` workers, at most 16), reading
the storage once per index in order, and reports the first bad entry in log order.
Its time grows with the bytes stored divided by the workers, not only with the
entries (see [limits](limits.md#time)). Errors:

- `ErrMissingHeader`, `ErrBadLogHeader`, `ErrEncodingMismatch`: the header
  is absent, not signed by `id`, or was created with another encoding.
- `ErrRestoreMismatch`: the head, a record, a ciphertext, a key or a delete
  marker does not match, an entry has both or neither of a ciphertext and a
  marker, a deleted entry has a key, or a live entry of an own log has none.
  The error names the index.
- `ErrRollback`: with `WithTrustedHead(h)`, the snapshot is older than `h`
  or forks from it. Use the newest head the caller has seen, so a restored
  log never re-signs an index that was already published. Every trusted
  head given is checked.
- `ErrLogOpen`: a writable log with this author key and log ID is already
  open, that pair is reserved, or the log ID is reserved with `ReserveID`.
- `ErrNoStorage` for a nil storage, and an error from the storage, such as
  a missing entry, wrapped. Anything malformed wraps `ErrMalformed`.

## Checking one entry

`OpenEntry(h, proof, e)` checks an entry fetched on its own against a
`VerifiedHead` and the entry's inclusion proof in it, then returns its
stored bytes as `Get` does. The record, the ciphertext or marker and the
key go through the same checks as in `Update`, and the leaf through RFC
9162 inclusion. Errors: `ErrInvalidHead` for a zero head, `ErrBadProof`
for a proof that does not put the record in `h`, `ErrBadEntry` for a part
that does not match the record, then `ErrDeleted` for a valid delete
marker and `ErrKeyUnavailable` for an entry without its key.
