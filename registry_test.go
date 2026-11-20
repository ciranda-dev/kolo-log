package kololog

import (
	"errors"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
)

func TestReserve(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a")})
	if _, err := Reserve(x.id.PublicKey(), x.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Reserve while the New log is open: %v, want %v", err, ErrLogOpen)
	}
	x.log.Close()

	release, err := Reserve(x.id.PublicKey(), x.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(x.id.PublicKey(), x.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("second Reserve: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Restore while reserved: %v, want %v", err, ErrLogOpen)
	}
	release()
	release()

	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries))
	if err != nil {
		t.Fatalf("Restore after release: %v", err)
	}
	if _, err := Reserve(x.id.PublicKey(), x.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Reserve while the restored log is open: %v, want %v", err, ErrLogOpen)
	}
	l.Close()
	release, err = Reserve(x.id.PublicKey(), x.log.ID())
	if err != nil {
		t.Fatalf("Reserve after Close: %v", err)
	}
	release()
}

func TestReserveForRestore(t *testing.T) {
	x := export(t, Bytes, []any{[]byte("a")})
	x.log.Close()
	id := x.log.ID()

	opt, release, err := ReserveForRestore(x.id.PublicKey(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(x.id.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Reserve while reserved for restore: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("plain Restore while reserved for restore: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Restore(x.id, x.header, x.head.Encode()[:10], storeOf(x.entries), opt); !errors.Is(err, ErrMalformed) {
		t.Fatalf("failing Restore with the option: %v", err)
	}
	if _, err := Reserve(x.id.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatal("a failed Restore ended the reservation")
	}

	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), opt)
	if err != nil {
		t.Fatalf("Restore with the option: %v", err)
	}
	release()
	release()
	if _, err := Reserve(x.id.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatal("release after the takeover unregistered the log")
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), opt); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("second Restore with a used option: %v, want %v", err, ErrLogOpen)
	}
	l.Close()
	r, err := Reserve(x.id.PublicKey(), id)
	if err != nil {
		t.Fatalf("Reserve after Close: %v", err)
	}
	r()
}

func TestReserveForRestoreOtherLog(t *testing.T) {
	a := export(t, Bytes, []any{[]byte("a")})
	b := export(t, Bytes, []any{[]byte("b")})
	a.log.Close()
	b.log.Close()
	optA, releaseA, err := ReserveForRestore(a.id.PublicKey(), a.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	releaseB, err := Reserve(b.id.PublicKey(), b.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(b.id, b.header, b.head.Encode(), storeOf(b.entries), optA); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("option for log A took over log B: %v, want %v", err, ErrLogOpen)
	}
	releaseB()
	if _, err := Reserve(a.id.PublicKey(), a.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatal("restoring log B ended log A's reservation")
	}
}

func TestReservationOnlyForItsLog(t *testing.T) {
	a := export(t, Bytes, []any{[]byte("a")})
	b := export(t, Bytes, []any{[]byte("b")})
	a.log.Close()
	b.log.Close()
	optA, releaseA, err := ReserveForRestore(a.id.PublicKey(), a.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	l, err := Restore(b.id, b.header, b.head.Encode(), storeOf(b.entries), optA)
	if !errors.Is(err, ErrLogOpen) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("Restore of log B with log A's reservation: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Reserve(a.id.PublicKey(), a.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatal("log A's reservation ended")
	}
}

func TestReservationsUseKeyAndID(t *testing.T) {
	key1, key2 := newID(t), newID(t)
	l1 := newLogFor(t, key1, 0)
	id := l1.ID()

	if _, err := Reserve(key1.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Reserve(key1, A) while (key1, A) is open: %v, want %v", err, ErrLogOpen)
	}
	r2, err := Reserve(key2.PublicKey(), id)
	if err != nil {
		t.Fatalf("Reserve(key2, A) while only (key1, A) is open: %v", err)
	}
	r2()

	x := export(t, Bytes, []any{[]byte("a")})
	x.log.Close()
	other := newID(t)
	rOther, err := Reserve(other.PublicKey(), x.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	l, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries))
	if err != nil {
		t.Fatalf("a reservation for (key2, A) blocked Restore of (key1, A): %v", err)
	}
	l.Close()
	rOther()

	opt, release, err := ReserveForRestore(other.PublicKey(), x.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	l, err = Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries), opt)
	if !errors.Is(err, ErrLogOpen) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("takeover with a mismatched key: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Reserve(other.PublicKey(), x.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("the (other, A) reservation ended after a refused takeover: %v", err)
	}

	release1, err := Reserve(x.id.PublicKey(), x.log.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(x.id.PublicKey(), x.log.ID()); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("second Reserve(key1, A): %v, want %v", err, ErrLogOpen)
	}
	if _, err := Restore(x.id, x.header, x.head.Encode(), storeOf(x.entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Restore of (key1, A) while it is reserved: %v, want %v", err, ErrLogOpen)
	}
	release1()

	if _, err := Reserve(x.id.PublicKey()[:31], x.log.ID()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Reserve with a short key: %v, want %v", err, ErrMalformed)
	}
}

func TestReserveID(t *testing.T) {
	key1, key2 := newID(t), newID(t)
	l1 := newLogFor(t, key1, 0)
	id := l1.ID()
	if _, err := ReserveID(id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("ReserveID while (key1, A) is open: %v, want %v", err, ErrLogOpen)
	}
	l1.Close()

	r2, err := Reserve(key2.PublicKey(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveID(id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("ReserveID while (key2, A) is reserved: %v, want %v", err, ErrLogOpen)
	}
	r2()

	release, err := ReserveID(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveID(id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("second ReserveID: %v, want %v", err, ErrLogOpen)
	}
	if _, err := Reserve(key1.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Reserve(key1, A) while A is reserved: %v, want %v", err, ErrLogOpen)
	}
	if _, _, err := ReserveForRestore(key2.PublicKey(), id); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("ReserveForRestore(key2, A) while A is reserved: %v, want %v", err, ErrLogOpen)
	}
	header, h, entries := unregisteredExport(t, key2, id)
	if _, err := Restore(key2, header, h, storeOf(entries)); !errors.Is(err, ErrLogOpen) {
		t.Fatalf("Restore of (key2, A) while A is reserved: %v, want %v", err, ErrLogOpen)
	}
	release()
	release()

	other, err := Restore(key2, header, h, storeOf(entries))
	if err != nil {
		t.Fatalf("Restore of (key2, A) after release: %v", err)
	}
	other.Close()
	r, err := ReserveID(id)
	if err != nil {
		t.Fatalf("ReserveID after release and Close: %v", err)
	}
	r()
}

// unregisteredExport builds a stored log for (key, id) without registering it.
func unregisteredExport(t *testing.T, key *koloid.Identity, id LogID) (header, head []byte, entries []Entry) {
	t.Helper()
	l := &Log{id: key, pub: key.PublicKey(), logID: id, s: NewMemory()}
	l.header = LogHeader{LogKey: key.PublicKey(), LogID: id}
	var err error
	if l.header.Signature, err = key.Sign(HeaderContext, l.header.signed()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	e, err := l.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	return l.header.Encode(), h.Encode(), []Entry{e}
}
