package kololog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-log/internal/merkle"
)

// DeleteContext is the signing context of delete markers.
const DeleteContext = "kolo-log/delete/v0"

// DeleteMarker is the log owner's signed statement that the entry with this leaf hash was deleted.
type DeleteMarker struct {
	LogKey    ed25519.PublicKey
	LogID     LogID
	Index     uint64
	LeafHash  [HashSize]byte
	Signature []byte
}

// VerifyDeleteMarker reports whether m is pub's valid marker for record r of the log logID.
// It never panics on untrusted input.
func VerifyDeleteMarker(pub ed25519.PublicKey, logID LogID, r Record, m DeleteMarker) bool {
	return keysEqual(pub, m.LogKey) && keysEqual(pub, r.LogKey) &&
		m.LogID == logID && r.LogID == logID && m.Index == r.Index &&
		merkle.Equal(m.LeafHash, merkle.LeafHash(r.Encode())) &&
		koloid.Verify(pub, DeleteContext, m.signed(), m.Signature)
}

// Encode returns the canonical encoding of m.
func (m DeleteMarker) Encode() []byte {
	return append(m.signed(), m.Signature...)
}

// DecodeDeleteMarker parses an encoding made by [DeleteMarker.Encode].
func DecodeDeleteMarker(b []byte) (DeleteMarker, error) {
	d := kolocodec.NewDecoder(b)
	if err := readTag(d, DeleteContext); err != nil {
		return DeleteMarker{}, err
	}
	var m DeleteMarker
	var err error
	if m.LogKey, err = d.Fixed(ed25519.PublicKeySize); err != nil {
		return DeleteMarker{}, malformed(err)
	}
	if err := readArray(d, m.LogID[:]); err != nil {
		return DeleteMarker{}, err
	}
	if m.Index, err = d.Uvarint(); err != nil {
		return DeleteMarker{}, malformed(err)
	}
	if err := readArray(d, m.LeafHash[:]); err != nil {
		return DeleteMarker{}, err
	}
	if m.Signature, err = d.Fixed(ed25519.SignatureSize); err != nil {
		return DeleteMarker{}, malformed(err)
	}
	if err := d.Done(); err != nil {
		return DeleteMarker{}, malformed(err)
	}
	return m, nil
}

func (m DeleteMarker) signed() []byte {
	var e kolocodec.Encoder
	e.PutString(DeleteContext)
	e.PutFixed(m.LogKey)
	e.PutFixed(m.LogID[:])
	e.PutUvarint(m.Index)
	e.PutFixed(m.LeafHash[:])
	return e.Bytes()
}

func (m DeleteMarker) clone() DeleteMarker {
	m.LogKey = slices.Clone(m.LogKey)
	m.Signature = slices.Clone(m.Signature)
	return m
}

type deleteMarkerJSON struct {
	LogKey    string `json:"logKey"`
	LogID     string `json:"logId"`
	Index     string `json:"index"`
	LeafHash  string `json:"leafHash"`
	Signature string `json:"signature"`
}

// MarshalJSON encodes m as a JSON view; the binary encoding is the only one that is signed.
func (m DeleteMarker) MarshalJSON() ([]byte, error) {
	return json.Marshal(deleteMarkerJSON{
		LogKey:    hex.EncodeToString(m.LogKey),
		LogID:     m.LogID.String(),
		Index:     strconv.FormatUint(m.Index, 10),
		LeafHash:  hex.EncodeToString(m.LeafHash[:]),
		Signature: hex.EncodeToString(m.Signature),
	})
}

// UnmarshalJSON strictly decodes the view made by [DeleteMarker.MarshalJSON].
func (m *DeleteMarker) UnmarshalJSON(b []byte) error {
	f, err := readObject(b, maxSmallJSON, "logKey", "logId", "index", "leafHash", "signature")
	if err != nil {
		return err
	}
	var out DeleteMarker
	if out.LogKey, err = hexField(f["logKey"], "logKey", ed25519.PublicKeySize); err != nil {
		return err
	}
	if err := hexArray(f["logId"], "logId", out.LogID[:]); err != nil {
		return err
	}
	if out.Index, err = uintField(f["index"], "index"); err != nil {
		return err
	}
	if err := hexArray(f["leafHash"], "leafHash", out.LeafHash[:]); err != nil {
		return err
	}
	if out.Signature, err = hexField(f["signature"], "signature", ed25519.SignatureSize); err != nil {
		return err
	}
	*m = out
	return nil
}

// String returns a short summary of m.
func (m DeleteMarker) String() string {
	return fmt.Sprintf("kololog.DeleteMarker{log=%s, index=%d, leaf=%s}", abbrev(m.LogID[:]), m.Index, abbrev(m.LeafHash[:]))
}

// LogValue returns m as a slog group with full hex values.
func (m DeleteMarker) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("logKey", hex.EncodeToString(m.LogKey)),
		slog.String("logId", m.LogID.String()),
		slog.Uint64("index", m.Index),
		slog.String("leafHash", hex.EncodeToString(m.LeafHash[:])),
		slog.String("signature", hex.EncodeToString(m.Signature)),
	)
}
