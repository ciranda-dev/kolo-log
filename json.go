package kololog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/ciranda-dev/kolo-log/internal/merkle"
	"github.com/ciranda-dev/kolo-log/internal/strictjson"
)

// ErrNotDecodable is returned by [VerifiedHead.UnmarshalJSON], always.
var ErrNotDecodable = errors.New("kololog: a VerifiedHead cannot be decoded; decode a Head and call VerifyHead")

// String returns the log ID as lowercase hex.
func (id LogID) String() string { return hex.EncodeToString(id[:]) }

// LogValue returns the log ID as lowercase hex.
func (id LogID) LogValue() slog.Value { return slog.StringValue(id.String()) }

// MarshalJSON encodes the log ID as a lowercase hex string.
func (id LogID) MarshalJSON() ([]byte, error) { return json.Marshal(id.String()) }

// UnmarshalJSON decodes a lowercase hex string of exactly 32 bytes.
func (id *LogID) UnmarshalJSON(b []byte) error {
	raw, err := strictjson.Value(b, maxSmallJSON, "log ID")
	if err != nil {
		return jsonErr(err)
	}
	v, err := hexField(raw, "log ID", LogIDSize)
	if err != nil {
		return err
	}
	copy(id[:], v)
	return nil
}

type headJSON struct {
	LogKey    string `json:"logKey"`
	LogID     string `json:"logId"`
	Size      string `json:"size"`
	Root      string `json:"root"`
	Signature string `json:"signature"`
}

// MarshalJSON encodes h as a JSON view; the binary encoding is the only one that is signed.
func (h Head) MarshalJSON() ([]byte, error) {
	return json.Marshal(headJSON{
		LogKey:    hex.EncodeToString(h.LogKey),
		LogID:     h.LogID.String(),
		Size:      strconv.FormatUint(h.Size, 10),
		Root:      hex.EncodeToString(h.Root[:]),
		Signature: hex.EncodeToString(h.Signature),
	})
}

// UnmarshalJSON strictly decodes the view made by [Head.MarshalJSON]; verify the result with [VerifyHead].
func (h *Head) UnmarshalJSON(b []byte) error {
	f, err := readObject(b, maxSmallJSON, "logKey", "logId", "size", "root", "signature")
	if err != nil {
		return err
	}
	var out Head
	if out.LogKey, err = hexField(f["logKey"], "logKey", ed25519.PublicKeySize); err != nil {
		return err
	}
	if err := hexArray(f["logId"], "logId", out.LogID[:]); err != nil {
		return err
	}
	if out.Size, err = uintField(f["size"], "size"); err != nil {
		return err
	}
	if err := hexArray(f["root"], "root", out.Root[:]); err != nil {
		return err
	}
	if out.Signature, err = hexField(f["signature"], "signature", ed25519.SignatureSize); err != nil {
		return err
	}
	*h = out
	return nil
}

// String returns a short summary of h.
func (h Head) String() string {
	return fmt.Sprintf("kololog.Head{log=%s, size=%d, root=%s}", abbrev(h.LogID[:]), h.Size, abbrev(h.Root[:]))
}

// LogValue returns h as a slog group with full hex values.
func (h Head) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("logKey", hex.EncodeToString(h.LogKey)),
		slog.String("logId", h.LogID.String()),
		slog.Uint64("size", h.Size),
		slog.String("root", hex.EncodeToString(h.Root[:])),
		slog.String("signature", hex.EncodeToString(h.Signature)),
	)
}

// MarshalJSON encodes v like [Head.MarshalJSON].
func (v VerifiedHead) MarshalJSON() ([]byte, error) { return v.head.MarshalJSON() }

// UnmarshalJSON always returns [ErrNotDecodable].
func (v *VerifiedHead) UnmarshalJSON([]byte) error { return ErrNotDecodable }

// String returns a short summary of v.
func (v VerifiedHead) String() string {
	return fmt.Sprintf("kololog.VerifiedHead{log=%s, size=%d, root=%s}", abbrev(v.head.LogID[:]), v.head.Size, abbrev(v.head.Root[:]))
}

// LogValue returns v like [Head.LogValue].
func (v VerifiedHead) LogValue() slog.Value { return v.head.LogValue() }

type recordJSON struct {
	LogKey      string `json:"logKey"`
	LogID       string `json:"logId"`
	Index       string `json:"index"`
	Size        string `json:"size"`
	ContentHash string `json:"contentHash"`
	KeyCommit   string `json:"keyCommit"`
	Signature   string `json:"signature"`
}

// MarshalJSON encodes r as a JSON view; the binary encoding is the only one that is signed.
func (r Record) MarshalJSON() ([]byte, error) {
	return json.Marshal(recordJSON{
		LogKey:      hex.EncodeToString(r.LogKey),
		LogID:       r.LogID.String(),
		Index:       strconv.FormatUint(r.Index, 10),
		Size:        strconv.FormatUint(r.Size, 10),
		ContentHash: hex.EncodeToString(r.ContentHash[:]),
		KeyCommit:   hex.EncodeToString(r.KeyCommit[:]),
		Signature:   hex.EncodeToString(r.Signature),
	})
}

// UnmarshalJSON strictly decodes the view made by [Record.MarshalJSON].
func (r *Record) UnmarshalJSON(b []byte) error {
	f, err := readObject(b, maxSmallJSON, "logKey", "logId", "index", "size", "contentHash", "keyCommit", "signature")
	if err != nil {
		return err
	}
	var out Record
	if out.LogKey, err = hexField(f["logKey"], "logKey", ed25519.PublicKeySize); err != nil {
		return err
	}
	if err := hexArray(f["logId"], "logId", out.LogID[:]); err != nil {
		return err
	}
	if out.Index, err = uintField(f["index"], "index"); err != nil {
		return err
	}
	if out.Size, err = uintField(f["size"], "size"); err != nil {
		return err
	}
	if err := hexArray(f["contentHash"], "contentHash", out.ContentHash[:]); err != nil {
		return err
	}
	if err := hexArray(f["keyCommit"], "keyCommit", out.KeyCommit[:]); err != nil {
		return err
	}
	if out.Signature, err = hexField(f["signature"], "signature", ed25519.SignatureSize); err != nil {
		return err
	}
	*r = out
	return nil
}

// String returns a short summary of r.
func (r Record) String() string {
	return fmt.Sprintf("kololog.Record{log=%s, index=%d, size=%d, content=%s}", abbrev(r.LogID[:]), r.Index, r.Size, abbrev(r.ContentHash[:]))
}

// LogValue returns r as a slog group with full hex values.
func (r Record) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("logKey", hex.EncodeToString(r.LogKey)),
		slog.String("logId", r.LogID.String()),
		slog.Uint64("index", r.Index),
		slog.Uint64("size", r.Size),
		slog.String("contentHash", hex.EncodeToString(r.ContentHash[:])),
		slog.String("keyCommit", hex.EncodeToString(r.KeyCommit[:])),
		slog.String("signature", hex.EncodeToString(r.Signature)),
	)
}

type inclusionJSON struct {
	Index string   `json:"index"`
	Size  string   `json:"size"`
	Path  []string `json:"path"`
}

// MarshalJSON encodes p as a JSON view.
func (p InclusionProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(inclusionJSON{
		Index: strconv.FormatUint(p.Index, 10),
		Size:  strconv.FormatUint(p.Size, 10),
		Path:  hexPath(p.Path),
	})
}

// UnmarshalJSON strictly decodes the view made by [InclusionProof.MarshalJSON].
func (p *InclusionProof) UnmarshalJSON(b []byte) error {
	f, err := readObject(b, maxProofJSON, "index", "size", "path")
	if err != nil {
		return err
	}
	var out InclusionProof
	if out.Index, err = uintField(f["index"], "index"); err != nil {
		return err
	}
	if out.Size, err = uintField(f["size"], "size"); err != nil {
		return err
	}
	if out.Path, err = pathField(f["path"]); err != nil {
		return err
	}
	*p = out
	return nil
}

// String returns a short summary of p.
func (p InclusionProof) String() string {
	return fmt.Sprintf("kololog.InclusionProof{index=%d, size=%d, path=%d hashes}", p.Index, p.Size, len(p.Path))
}

// LogValue returns p as a slog group with full hex values.
func (p InclusionProof) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("index", p.Index),
		slog.Uint64("size", p.Size),
		slog.Any("path", hexPath(p.Path)),
	)
}

type consistencyJSON struct {
	OldSize string   `json:"oldSize"`
	NewSize string   `json:"newSize"`
	Path    []string `json:"path"`
}

// MarshalJSON encodes p as a JSON view.
func (p ConsistencyProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(consistencyJSON{
		OldSize: strconv.FormatUint(p.OldSize, 10),
		NewSize: strconv.FormatUint(p.NewSize, 10),
		Path:    hexPath(p.Path),
	})
}

// UnmarshalJSON strictly decodes the view made by [ConsistencyProof.MarshalJSON].
func (p *ConsistencyProof) UnmarshalJSON(b []byte) error {
	f, err := readObject(b, maxProofJSON, "oldSize", "newSize", "path")
	if err != nil {
		return err
	}
	var out ConsistencyProof
	if out.OldSize, err = uintField(f["oldSize"], "oldSize"); err != nil {
		return err
	}
	if out.NewSize, err = uintField(f["newSize"], "newSize"); err != nil {
		return err
	}
	if out.Path, err = pathField(f["path"]); err != nil {
		return err
	}
	*p = out
	return nil
}

// String returns a short summary of p.
func (p ConsistencyProof) String() string {
	return fmt.Sprintf("kololog.ConsistencyProof{old=%d, new=%d, path=%d hashes}", p.OldSize, p.NewSize, len(p.Path))
}

// LogValue returns p as a slog group with full hex values.
func (p ConsistencyProof) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("oldSize", p.OldSize),
		slog.Uint64("newSize", p.NewSize),
		slog.Any("path", hexPath(p.Path)),
	)
}

func abbrev(b []byte) string {
	if len(b) > 8 {
		return hex.EncodeToString(b[:8]) + "..."
	}
	return hex.EncodeToString(b)
}

func hexPath(path [][HashSize]byte) []string {
	out := make([]string, 0, len(path))
	for _, h := range path {
		out = append(out, hex.EncodeToString(h[:]))
	}
	return out
}

func malformedJSON(what string) error {
	return fmt.Errorf("%w: json %s", ErrMalformed, what)
}

func jsonErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

// Size caps, well above the largest valid encoding of each type.
const (
	maxSmallJSON = 4 << 10
	maxProofJSON = 8 << 10
)

func readObject(b []byte, max int, keys ...string) (map[string]json.RawMessage, error) {
	f, err := strictjson.Object(b, max, keys...)
	return f, jsonErr(err)
}

func readObjectWith(b []byte, keys []string, optional ...string) (map[string]json.RawMessage, error) {
	f, err := strictjson.ObjectWith(b, maxSmallJSON, keys, optional)
	return f, jsonErr(err)
}

func stringField(raw json.RawMessage, name string) (string, error) {
	s, err := strictjson.String(raw, name)
	return s, jsonErr(err)
}

func hexField(raw json.RawMessage, name string, n int) ([]byte, error) {
	b, err := strictjson.Hex(raw, name, n)
	return b, jsonErr(err)
}

func hexArray(raw json.RawMessage, name string, dst []byte) error {
	return jsonErr(strictjson.HexInto(raw, name, dst))
}

func uintField(raw json.RawMessage, name string) (uint64, error) {
	v, err := strictjson.Uint(raw, name)
	return v, jsonErr(err)
}

func pathField(raw json.RawMessage) ([][HashSize]byte, error) {
	p, err := strictjson.Path(raw, merkle.MaxPathLen)
	return p, jsonErr(err)
}
