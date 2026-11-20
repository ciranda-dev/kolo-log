package entrycrypt

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"testing"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestPadme(t *testing.T) {
	tests := []struct{ n, want uint64 }{
		{0, 0}, {1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {7, 7},
		{8, 8}, {9, 10}, {15, 16}, {16, 16}, {17, 18},
		{31, 32}, {32, 32}, {33, 36}, {63, 64}, {64, 64}, {65, 72},
		{100, 104}, {127, 128}, {128, 128}, {129, 144},
		{255, 256}, {256, 256}, {257, 272},
		{511, 512}, {512, 512}, {513, 544},
		{1000, 1024}, {1023, 1024}, {1024, 1024}, {1025, 1088},
		{65535, 65536}, {65536, 65536}, {65537, 67584},
		{1<<20 + 1, 1081344},
	}
	for _, tt := range tests {
		if got := Padme(tt.n); got != tt.want {
			t.Errorf("Padme(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
	frames := []struct{ n, want uint64 }{
		{0, 256}, {1, 256}, {11, 256}, {255, 256}, {256, 256}, {257, 272}, {1000, 1024},
	}
	for _, tt := range frames {
		if got := FrameLen(tt.n); got != tt.want {
			t.Errorf("FrameLen(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestPadmeOverhead(t *testing.T) {
	for n := uint64(MinFrame); n <= 64<<10; n++ {
		p := FrameLen(n)
		if p < n {
			t.Fatalf("FrameLen(%d) = %d is shorter than its input", n, p)
		}
		if float64(p-n)/float64(n) >= 0.07 {
			t.Fatalf("FrameLen(%d) = %d: overhead of 7%% or more", n, p)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	lengths := []int{0, 1, 1000, 65536}
	for n := 249; n <= 260; n++ {
		lengths = append(lengths, n)
	}
	_, aead, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range lengths {
		data := bytes.Repeat([]byte{0x5a}, n)
		var e kolocodec.Encoder
		e.PutUvarint(uint64(n))
		f := Frame(data)
		if want := FrameLen(uint64(len(e.Bytes()) + n)); uint64(len(f)) != want {
			t.Fatalf("%d bytes: frame of %d bytes, want %d", n, len(f), want)
		}
		got, err := Unframe(f)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: unframe = %d bytes, %v", n, len(got), err)
		}
		sealed, err := Seal(aead, nil, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != len(f)+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
			t.Fatalf("%d bytes: sealed size %d, want %d", n, len(sealed), len(f)+40)
		}
		got, err = Open(aead, nil, sealed)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: open = %d bytes, %v", n, len(got), err)
		}
	}
}

func TestOpenTampered(t *testing.T) {
	key, aead, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	var logID [32]byte
	ad := AD(make([]byte, 32), logID, 7)
	sealed, err := Seal(aead, ad, []byte("hello kolo"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(aead, ad, sealed); err != nil || string(got) != "hello kolo" {
		t.Fatalf("open = %q, %v", got, err)
	}
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := Open(aead, ad, bad); !errors.Is(err, ErrAuth) {
			t.Fatalf("byte %d flipped: open returned %v, want %v", i, err, ErrAuth)
		}
	}
	for n := range len(sealed) {
		if _, err := Open(aead, ad, sealed[:n]); !errors.Is(err, ErrAuth) {
			t.Fatalf("truncated to %d bytes: open returned %v", n, err)
		}
	}
	if _, err := Open(aead, AD(make([]byte, 32), logID, 8), sealed); !errors.Is(err, ErrAuth) {
		t.Fatal("ciphertext opened under another index")
	}
	_, other, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(other, ad, sealed); !errors.Is(err, ErrAuth) {
		t.Fatal("ciphertext opened under another key")
	}
}

func TestSealFreshNonce(t *testing.T) {
	aead, err := chacha20poly1305.NewX(make([]byte, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Seal(aead, nil, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(aead, nil, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are equal")
	}
}

func TestCheckSize(t *testing.T) {
	limit := uint64(MaxFrame)
	if strconv.IntSize == 32 {
		limit = (math.MaxInt - SealOverhead) / 4
	}
	if FrameLimit != limit {
		t.Fatalf("FrameLimit = %d, want %d on a %d-bit platform", uint64(FrameLimit), limit, strconv.IntSize)
	}

	lo, hi := uint64(0), limit
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if CheckSize(mid) == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	var e kolocodec.Encoder
	e.PutUvarint(lo)
	if got := FrameLen(uint64(len(e.Bytes())) + lo); got > limit {
		t.Fatalf("largest accepted size %d pads to %d, over %d", lo, got, limit)
	}
	for _, n := range []uint64{lo + 1, limit, MaxFrame, 1 << 40, 1<<64 - 1} {
		if err := CheckSize(n); !errors.Is(err, ErrTooLarge) {
			t.Errorf("CheckSize(%d) = %v, want %v", n, err, ErrTooLarge)
		}
	}
	for _, n := range []uint64{0, 1, 1 << 20, lo} {
		if err := CheckSize(n); err != nil {
			t.Errorf("CheckSize(%d) = %v, want nil", n, err)
		}
	}
	t.Logf("largest entry accepted: %d bytes (%.1f GiB)", lo, float64(lo)/(1<<30))
}

func FuzzOpen(f *testing.F) {
	// A fixed key and nonce keep the seed identical in every fuzz worker.
	aead, err := chacha20poly1305.NewX(make([]byte, KeySize))
	if err != nil {
		f.Fatal(err)
	}
	var logID [32]byte
	ad := AD(make([]byte, 32), logID, 0)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	sealed := aead.Seal(nonce, nonce, Frame([]byte("hello kolo")), ad)
	f.Add(sealed)
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Open(aead, ad, b)
		if err == nil && !bytes.Equal(b, sealed) {
			t.Fatalf("forged ciphertext opened to %q", got)
		}
	})
}

func FuzzUnframe(f *testing.F) {
	f.Add(Frame([]byte("hello kolo")))
	f.Add(Frame(make([]byte, 300)))
	f.Add([]byte{0xac, 0x02})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Unframe(b)
		if err != nil {
			return
		}
		if !bytes.Equal(Frame(got), b) {
			t.Fatalf("unframe accepted a non-canonical frame of %d bytes", len(b))
		}
	})
}

func TestFromKey(t *testing.T) {
	key, aead, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	ad := AD(make([]byte, 32), [32]byte{1}, 3)
	sealed, err := Seal(aead, ad, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	k2, aead2, err := FromKey(key[:])
	if err != nil || *k2 != *key {
		t.Fatalf("FromKey: %v", err)
	}
	if got, err := Open(aead2, ad, sealed); err != nil || string(got) != "hello" {
		t.Fatalf("Open with a copied key = %q, %v", got, err)
	}
	for _, n := range []int{0, 31, 33} {
		if _, _, err := FromKey(make([]byte, n)); !errors.Is(err, ErrAuth) {
			t.Errorf("FromKey of %d bytes: %v, want ErrAuth", n, err)
		}
	}
}
