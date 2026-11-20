package kololog

import (
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ciranda-dev/kolo-log/internal/entrycrypt"
)

// ErrMalformedEntry is returned by [Log.Get] when a stored ciphertext does not open to a valid entry.
var ErrMalformedEntry = errors.New("kololog: malformed entry")

// ErrEntryTooLarge is returned by [Log.Append] for an entry over the size cap.
// The cap is about 254 GiB on 64-bit and about 512 MiB on 32-bit platforms.
var ErrEntryTooLarge = errors.New("kololog: entry too large")

var (
	errDecrypt = fmt.Errorf("%w: authentication failed", ErrMalformedEntry)
	errFrame   = fmt.Errorf("%w: bad length or padding", ErrMalformedEntry)
)

const keySize = entrycrypt.KeySize

// entryErr maps entrycrypt errors to the package's exported ones.
func entryErr(err error) error {
	switch {
	case errors.Is(err, entrycrypt.ErrAuth):
		return errDecrypt
	case errors.Is(err, entrycrypt.ErrFrame):
		return errFrame
	case errors.Is(err, entrycrypt.ErrTooLarge):
		return ErrEntryTooLarge
	}
	return err
}

func checkEntrySize(n uint64) error {
	return entryErr(entrycrypt.CheckSize(n))
}

func entryAD(logKey ed25519.PublicKey, logID LogID, index uint64) []byte {
	return entrycrypt.AD(logKey, logID, index)
}

func openFrame(aead cipher.AEAD, ad, sealed []byte) (f, data []byte, err error) {
	f, data, err = entrycrypt.OpenFrame(aead, ad, sealed)
	return f, data, entryErr(err)
}
