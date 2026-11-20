package kololog

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// leakForms are the ways fmt, slog and encoders can spell b.
func leakForms(b []byte) []string {
	b64 := base64.StdEncoding.EncodeToString(b)
	q := fmt.Sprintf("%q", b)
	dec := fmt.Sprint(b)
	return []string{hex.EncodeToString(b), fmt.Sprintf("%X", b), b64[:len(b64)-4], dec[1 : len(dec)-1], q[1 : len(q)-1], string(b)}
}

func printAll(out *bytes.Buffer, v any) {
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%e", "%c", "%U", "%o", "%b", "%f", "%g", "%T"} {
		fmt.Fprintf(out, verb+"\n", v)
	}
	fmt.Fprintln(out, v)
	slog.New(slog.NewTextHandler(out, nil)).Info("v", "v", v, slog.Any("any", v))
	slog.New(slog.NewJSONHandler(out, nil)).Info("v", "v", v, slog.Any("any", v))
	if j, err := json.Marshal(v); err == nil {
		out.Write(j)
	}
}

// TestRedaction prints every type that holds a secret, a PRK or entry keys, alone and as exported and unexported fields,
// and finds none of them in the output, except where the docs say fmt prints raw bytes.
func TestRedaction(t *testing.T) {
	var secret EntrySecret
	for i := range secret {
		secret[i] = byte(0xa0 + i)
	}
	p, err := newPRK(&secret)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := newDerivedLog(t, NewMemory(), &secret, 0, 3)
	d := deriverOf(t, l, &secret)
	r := keylessReplica(t, l, NewMemory())
	if err := r.AddKeys(0, derivedKeys(t, d, 0, 3)); err != nil {
		t.Fatal(err)
	}
	var keys [][]byte
	for i := range l.Len() {
		k, err := l.Key(i)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	rl, _ := newLog(t, 2) // random keys, over a memory storage
	for i := range rl.Len() {
		keys = append(keys, mustEntry(t, rl, i).Key)
	}
	vs := &valueStorage{}
	vl, err := New(newID(t), vs)
	if err != nil {
		t.Fatal(err)
	}
	defer vl.Close()
	appendN(t, vl, 0, 2)
	for i := range vl.Len() {
		keys = append(keys, mustEntry(t, vl, i).Key)
	}
	ka := KeyAt{Index: 0, Key: keys[0]}
	ch := Change{Keys: []KeyAt{ka}, Entries: []Entry{mustEntry(t, rl, 0)}}
	bad := &BadKeyError{Indexes: []uint64{1}}

	type exported struct {
		L  *Log
		R  *Replica
		D  *KeyDeriver
		S  EntrySecret
		SP *EntrySecret
		K  KeyAt
		C  Change
		E  error
	}
	type unexported struct {
		l *Log
		r *Replica
		d *KeyDeriver
		m Storage
	}
	cases := []struct {
		name               string
		v                  any
		secretRaw, keysRaw bool // printed raw, as the docs say
	}{
		{"*Log", l, false, false},
		{"Log", reflect.ValueOf(l).Elem().Interface(), false, false},
		{"*Log with random keys", rl, false, false},
		{"*Log over a storage that keeps keys by value", vl, false, false},
		{"unexported *Log over that storage", struct{ l *Log }{vl}, false, false},
		{"*Replica", r, false, false},
		{"Replica", reflect.ValueOf(r).Elem().Interface(), false, false},
		{"*KeyDeriver", d, false, false},
		{"KeyDeriver", reflect.ValueOf(d).Elem().Interface(), false, false},
		{"EntrySecret", secret, false, false},
		{"*EntrySecret", &secret, false, false},
		{"memory storage", l.s, false, false},
		{"KeyAt", ka, false, false},
		{"Change", ch, false, false},
		{"*BadKeyError", bad, false, false},
		{"exported fields", exported{L: l, R: r, D: d, S: secret, SP: &secret, K: ka, C: ch, E: bad}, false, false},
		{"&exported fields", &exported{L: l, R: r, D: d, S: secret, SP: &secret, K: ka, C: ch, E: bad}, false, false},
		{"unexported fields", unexported{l: l, r: r, d: d, m: l.s}, false, false},
		{"&unexported fields", &unexported{l: l, r: r, d: d, m: rl.s}, false, false},
		{"unexported EntrySecret", struct{ s EntrySecret }{secret}, true, false},
		{"unexported *EntrySecret", struct{ s *EntrySecret }{&secret}, true, false},
		{"unexported KeyAt", struct{ k KeyAt }{ka}, false, true},
		{"unexported Change", struct{ c Change }{ch}, false, true},
	}
	for _, c := range cases {
		var out bytes.Buffer
		printAll(&out, c.v)
		s := out.String()
		check := func(what string, b []byte) {
			for _, form := range leakForms(b) {
				if strings.Contains(s, form) {
					t.Errorf("%s: %s printed as %q", c.name, what, form)
					return
				}
			}
		}
		check("PRK", p.key()[:])
		check("log PRK", l.prk.key()[:])
		if !c.secretRaw {
			check("secret", secret[:])
		}
		if !c.keysRaw {
			for i, k := range keys {
				check(fmt.Sprintf("entry key %d", i), k)
			}
		}
	}
	for v, want := range map[any]string{secret: redacted, &secret: redacted, d: redacted, l: "kololog.Log{", r: "kololog.Replica{", l.s: "kololog.memory{"} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			if got := fmt.Sprintf(verb, v); !strings.HasPrefix(got, want) {
				t.Errorf("%s of %T = %s, want %s", verb, v, got, want)
			}
		}
	}
	if j, err := json.Marshal(secret); err != nil || string(j) != `"[redacted]"` {
		t.Errorf("EntrySecret JSON = %s, %v", j, err)
	}

	// Errors that involve the secret or keys name neither.
	var errs bytes.Buffer
	_, err = NewKeyDeriver(&secret, newID(t).PublicKey(), l.Header())
	fmt.Fprintf(&errs, "%v %+v %#v\n", err, err, err)
	err = r.AddKeys(0, []EntryKey{secret[:], p.key()[:]})
	fmt.Fprintf(&errs, "%v %+v %#v\n", err, err, err)
	for _, b := range [][]byte{secret[:], p.key()[:]} {
		for _, form := range leakForms(b) {
			if strings.Contains(errs.String(), form) {
				t.Fatalf("an error printed %q", form)
			}
		}
	}
}

// fmt handles %p before Format, so %p of a value holding key bytes prints them: the docs say so, and this test notices if Go changes it.
func TestPercentPPrintsValues(t *testing.T) {
	secret := *testSecret(0xc5)
	key := EntryKey(bytes.Repeat([]byte{0xc6}, keySize))
	for name, c := range map[string]struct {
		v    any
		want []byte
	}{
		"EntrySecret": {secret, secret[:]},
		"KeyAt":       {KeyAt{Key: key}, key},
		"Entry":       {Entry{Key: key}, key},
	} {
		if s := fmt.Sprintf("%p", c.v); !strings.Contains(s, fmt.Sprint([]byte(c.want))[1:20]) {
			t.Errorf("%%p of %s no longer prints its bytes (%s): update docs/guide.md and docs/limits.md", name, s)
		}
	}
	if s := fmt.Sprintf("%p", &secret); strings.Contains(s, "197 197") {
		t.Errorf("%%p of *EntrySecret printed bytes: %s", s)
	}
}

// reachable collects every byte a reflection-based dumper (one that bypasses methods and reads unexported fields) can reach from v.
func reachable(v reflect.Value, seen map[uintptr]bool, out *bytes.Buffer) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		reachable(v.Elem(), seen, out)
	case reflect.Interface:
		if !v.IsNil() {
			reachable(v.Elem(), seen, out)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			reachable(v.Field(i), seen, out)
		}
	case reflect.Array, reflect.Slice:
		for i := range v.Len() {
			if e := v.Index(i); e.Kind() == reflect.Uint8 {
				out.WriteByte(byte(e.Uint()))
			} else {
				reachable(e, seen, out)
			}
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			reachable(it.Key(), seen, out)
			reachable(it.Value(), seen, out)
		}
	}
}

// The PRK lives in a closure, which reflection cannot enter, so dumpers that bypass methods never reach it.
func TestPRKOutOfReflection(t *testing.T) {
	secret := testSecret(0xb1)
	l, _ := newDerivedLog(t, NewMemory(), secret, 0, 1)
	d := deriverOf(t, l, secret)
	for name, v := range map[string]any{"*Log": l, "*KeyDeriver": d} {
		var out bytes.Buffer
		reachable(reflect.ValueOf(v), map[uintptr]bool{}, &out)
		if out.Len() == 0 {
			t.Fatalf("%s: the walk reached nothing", name)
		}
		if bytes.Contains(out.Bytes(), l.prk.key()[:16]) {
			t.Errorf("%s: reflection reaches the PRK", name)
		}
	}
}

// valueStorage keeps entries by value, keys included, as a Storage outside kolo-log may.
type valueStorage struct {
	mu      sync.Mutex
	entries []Entry
}

func (s *valueStorage) Entry(index uint64) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= uint64(len(s.entries)) {
		return Entry{}, ErrOutOfRange
	}
	return cloneEntry(s.entries[index]), nil
}

func (s *valueStorage) Key(index uint64) (EntryKey, error) {
	e, err := s.Entry(index)
	return e.Key, err
}

func (s *valueStorage) Commit(c Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range c.Entries {
		s.entries = append(s.entries, cloneEntry(e))
	}
	return nil
}
