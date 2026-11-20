# Limits

Every bound in kolo-log, with its value. This page is reference material: the README does not repeat it.

## Entries

| What | Value | Error |
|---|---|---|
| Entry size | about 254 GiB (about 512 MiB on 32-bit platforms) | `ErrEntryTooLarge` |
| Size of an entry on disk | an entry of up to 254 bytes is padded to a 256-byte frame, and its stored ciphertext is 296 bytes (a 24-byte nonce and a 16-byte tag more); larger frames are rounded up with Padmé, at most about 6% extra | |
| Log ID | 32 bytes, random | |
| Entry key | 32 bytes | |
| Entry secret of a log with derived keys | 32 uniformly random bytes | |
| Epoch | any `uint64`, set by the caller | |
| Keys in one `Replica.AddKeys` call | 32,768 (`MaxAddKeys`): kolo-sync's 4 MiB message over its 128-byte smallest signed record, the most entries one answer carries | `ErrTooManyKeys` |
| Writable logs per (author key, log ID) in a process | one | `ErrLogOpen` |

## Memory

A log or replica keeps in memory only what proofs and checks need. Memory grows with the number of entries, never with their size.

| What | Size per entry |
|---|---|
| Tree hashes | about 64 bytes |
| Compact record with its two flags (size, content hash, key commitment, signature, deleted, key stored) | 144 bytes |

Ciphertexts, keys and delete markers live in the `Storage`.

## Time

`Append` (two signatures), `Head` (one) and every proof take O(log² n) hashes at most and never read the stored entries, however long the log is.

`Restore` and `RestoreReplica` read every entry once, in order, and check all of it: one Ed25519 verification of its record, the BLAKE2b-256 hash of its ciphertext and, when its key is stored, that the key opens it. `Open` of a stored log in kolo-store runs one on every open. The checks run in parallel, with the same errors and the same result as one goroutine checking in turn:

- One goroutine asks the storage for each index once, in increasing order. `GOMAXPROCS` workers, at most 16 (`maxVerifyWorkers`), and never more than there are entries, check them. The results are applied to the tree in index order, so the error is always the one of the lowest failing index.
- Memory is bounded: the workers and the reader hold at most workers + 1 entries, so at most 17 times the largest entry (about 17 MiB for 1 MiB entries). The log still keeps only 208 bytes per entry.
- After the first failure the storage may be asked for up to 2 x workers + 1 more entries (33 at most) before the reader stops. Every key read is cleared on every path.
- Time is about the bytes stored divided by the workers, plus the time the storage takes to read them: the reader is one goroutine, so a slow storage is read at its own speed.

Measured with `go test -bench BenchmarkRestore` (`NewMemory` storage, Apple M5, 10 cores, on a loaded machine: load average 18 to 25 during the runs, so every number is slower than an idle machine would give, and they vary between runs). Median of 5 runs:

| Entries | 1 worker | 10 workers (the default here) | Speedup |
|---|---|---|---|
| 200 of 1 MiB (200 MiB) | 471 ms (424 MiB/s) | 164 ms (1,220 MiB/s) | 2.9x |
| 20,000 of 100 bytes | 1.38 s (69 microseconds per entry) | 140 ms (7 microseconds per entry); another run in the same session took 540 ms | 9.9x (2.5x in the slower run) |

Extrapolation, not a measurement: at the rates above, 100 GiB (102,400 MiB) is about 4 minutes with one worker and about 84 seconds with 10, plus the time the storage takes to read it. On an idle machine with more cores the time falls further, down to the speed of the storage; with fewer cores it grows towards the one-worker figure.

## JSON input

JSON is a view for APIs, debugging and config. It is never signed or verified. A value is rejected with an error that wraps `ErrMalformed` when:

- the input is over 4 KiB (8 KiB for proofs);
- a proof path has more than 65 hashes;
- a field is missing, unknown or duplicated;
- hex is uppercase or of the wrong length, or a string holds escape sequences;
- data follows the value.

A `VerifiedHead` cannot be decoded (`ErrNotDecodable`).

## Deletion

Deleting is best effort. It holds on every peer that follows the protocol and applies the delete marker; a peer that already received the entry key can keep it.

In a log with derived keys, anyone who holds the entry secret and kept a copy of an entry's ciphertext can still read it after it is deleted: a key that can be derived again cannot be destroyed.

- `Delete` with an index out of range deletes nothing, and entries already deleted are skipped.
- On kolo-store with Pebble, deleting 1,000 entries takes about 34 ms in one call against about 3.6 s one at a time.

## Keys in memory

- With the JSON encoding, `encoding/json` keeps its own internal buffers, which kolo-log cannot clear.
- `fmt` and `slog` show an `EntryKey` as `[redacted]` when it is passed on its own or reached through exported fields; inside an unexported struct field they print the raw bytes, and an encoder that ignores `MarshalJSON` (such as `encoding/gob`) writes the key in clear. `encoding/json` leaves `Entry.Key` out.
- The caller owns the copy of a key it gets and should clear it when done. `Commit` must copy what it keeps: the log zeroes the keys in the `Change` once it returns.
- `fmt` and `slog` show an `EntrySecret` and a `*KeyDeriver` as `[redacted]`, and a `*Log` and a `*Replica` as their log ID, encoding, key mode and epoch, for every verb. The PRK lives only in a closure, out of reach of fmt and of reflection.
- Printed or kept raw: an `EntrySecret` inside an unexported struct field (by value or behind one pointer); `%p` of an `EntrySecret`, `KeyAt`, `Change` or `Entry` value (fmt handles `%p` before `Format`); `encoding/gob` of an `EntrySecret` or `EntryKey`; dumpers that bypass methods (go-spew with `DisableMethods`, as in testify's diffs) print the secret and stored entry keys; go-cmp's diff prints an `EntrySecret` as hex. Every copy of the array is another copy of the secret, and the copy `WithDerivedKeys` makes lives as long as the `Option`. HMAC keeps its own copies of the PRK until the runtime reuses that memory.

## Errors on untrusted input

Every `Decode` function and verifier takes untrusted bytes and returns an error or false, never a panic.
