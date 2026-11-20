# Formats

The binary encoding (`Encode` and the `Decode` functions, built on
kolo-codec) is the only one that is signed, hashed, sent or stored. Heads,
records, delete markers and the log header are signed with Ed25519ctx
under their own contexts: `kolo-log/tree-head/v0`, `kolo-log/record/v1`,
`kolo-log/delete/v0`, and `kolo-log/header/v0` or
`kolo-log/derived-header/v0` for the header.

The log header has one form per key mode, each with its own tag and signing
context, so a header signed as one form never verifies as the other:

```text
random keys:  string "kolo-log/header/v0" | fixed[32] log key | fixed[32] log ID | uvarint value encoding | fixed[64] signature
derived keys: string "kolo-log/derived-header/v0" | fixed[32] log key | fixed[32] log ID | uvarint value encoding | uvarint epoch | fixed[64] signature
```

The random form is the header of every log before derived keys, byte for
byte. `DecodeLogHeader` reads the tag once and accepts exactly these two.
The key mode and the epoch are bound by the header only: records bind the
log key, the log ID and the index. A writer could sign two headers for one
log ID, which only harms its own log, because each record commits to one
key. A reader keeps the first verified header of a log and refuses another.

In a log with derived keys, the key of entry `index` is HKDF-SHA256
(RFC 5869) with an empty salt, the entry secret as input, 32 bytes of
output and the info
`string "kolo-log/entry-key/v0" | fixed[32] log key | fixed[32] log ID | uvarint epoch | uvarint index`.

A delete marker is
`string "kolo-log/delete/v0" | fixed[32] log key | fixed[32] log ID | uvarint index | fixed[32] leaf hash | fixed[64] signature`,
where the leaf hash is the tree leaf of the deleted entry's record. The tree uses RFC 9162 hashing with BLAKE2b-256.

Each entry is framed with its length and padded before encryption with
XChaCha20-Poly1305: every entry up to 254 bytes takes a 256-byte frame, and
larger ones are rounded up with Padmé (Nikitin et al., 2019), at most about 6%
extra. The ciphertext is the frame with a 24-byte nonce before it and a
16-byte tag after it. For every entry, the author key, the log ID, the index, the padded
size, the hash of the ciphertext and the key commitment are public, and for
every log its key mode and epoch. The content, its real size
and the time it was written are not, and this stays the same after the
entry is deleted. In a log with derived keys the key commitment is a
public function of the entry secret, so the secret must be uniformly random.

JSON is a view for APIs, debugging and config. It is never signed or
verified, and a `Head` read from JSON is trusted only after `VerifyHead`.

| Type | JSON |
|---|---|
| `Head` | `{"logKey","logId","size","root","signature"}` |
| `VerifiedHead` | same as `Head`, encode only |
| `Record` | `{"logKey","logId","index","size","contentHash","keyCommit","signature"}` |
| `InclusionProof` | `{"index","size","path":[...]}` |
| `ConsistencyProof` | `{"oldSize","newSize","path":[...]}` |
| `LogHeader` | `{"logKey","logId","encoding","signature"}`; with derived keys `{"logKey","logId","encoding","keys":"derived","epoch","signature"}` |
| `DeleteMarker` | `{"logKey","logId","index","leafHash","signature"}` |
| `LogID` | `"<64 hex chars>"` |

Bytes are lowercase hex of the exact length, and every `uint64` is a string
in plain decimal. Every field is required; a `LogHeader` has `keys` and
`epoch` together or neither, and `keys` is always `"derived"`, so each
header has one JSON form. Unknown or duplicate fields,
uppercase hex, escape sequences, trailing data, inputs over 4 KiB (8 KiB
for proofs) and paths of more than 65 hashes are rejected
with an error that wraps `ErrMalformed`. A `VerifiedHead` cannot be decoded
(`ErrNotDecodable`): decode a `Head` and call `VerifyHead`.

## References

- [RFC 9162, Certificate Transparency Version 2.0](https://www.rfc-editor.org/info/rfc9162) (Experimental, December 2021).
  Takes: tree hashing (2.1.1), inclusion and consistency proofs (2.1.3, 2.1.4) and the monitor that keeps every entry (8.2), which `Replica` follows.
  Not implemented: SHA-256 (BLAKE2b-256 instead) and timestamps in heads, so a replica orders heads by size and root only (an older head that matches the held entries is a rollback, any other root is a divergence). A replica checks both the consistency proof and the rebuilt root, and entries can be deleted behind a signed marker. `VerifyConsistency` also accepts an old size of 0 and equal sizes, where RFC 9162 defines proofs only for 0 < first < second. A replica checks consistency from a chunk size `m` that no signed head names, against the root it rebuilt itself from verified leaves.
- [RFC 7693, The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://www.rfc-editor.org/info/rfc7693) (Informational, November 2015).
  Takes: BLAKE2b with a 32-byte output for every hash.
  Not implemented: the keyed MAC mode.
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx (5.1, 8.3), with one context per signed encoding, listed under Formats.
  Not implemented: Ed25519ph.
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/info/rfc5869) (Informational, May 2010).
  Takes: extract and expand (2.2, 2.3) for the entry keys of a log with derived keys; an empty salt is a salt of zero bytes.
  Not implemented: nothing left out.
- [draft-irtf-cfrg-xchacha-03, XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) (Internet-Draft, expired, never an RFC).
  Takes: the AEAD of every frame.
  Not implemented: key commitment, replaced by a hash commitment in the signed record.
- Nikitin et al., [Reducing Metadata Leakage from Encrypted Files and Communication with PURBs](https://doi.org/10.2478/popets-2019-0056), PETS 2019.
  Takes: Padmé padding.
- Len, Grubbs and Ristenpart, [Partitioning Oracle Attacks](https://www.usenix.org/conference/usenixsecurity21/presentation/len), USENIX Security 2021, and Albertini et al., [How to Abuse and Fix Authenticated Encryption Without Key Commitment](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini), USENIX Security 2022.
  Takes: why the key needs a commitment, as AEADs such as XChaCha20-Poly1305 do not commit to the key.
  Not implemented: a committing frame; the signed record carries a hash commitment to the key instead, which any reader checks before decrypting.
- Boneh and Lipton, [A Revocable Backup System](https://www.usenix.org/conference/6th-usenix-security-symposium/revocable-backup-system), USENIX Security 1996.
  Takes: deletion by destroying the key.
  Not implemented: the key is kept next to the ciphertext by the storage layer, and deletion only holds on peers that follow the protocol; a peer that already received a key can keep it.
