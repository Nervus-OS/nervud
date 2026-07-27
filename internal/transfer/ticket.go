package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

func randomBytes(src io.Reader, n int) ([]byte, error) {
	if src == nil {
		src = rand.Reader
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(src, out); err != nil {
		return nil, fmt.Errorf("transfer: random bytes: %w", err)
	}
	return out, nil
}

func ticketDigest(ticket []byte) [32]byte {
	return sha256.Sum256(ticket)
}

func ticketMatches(want [32]byte, got []byte) bool {
	if len(got) < attachTicketBytes {
		// Still hash the attacker-controlled value before deciding so the
		// stored digest is never compared to a variable-length prefix.
		d := sha256.Sum256(got)
		_ = subtle.ConstantTimeCompare(want[:], d[:])
		return false
	}
	d := sha256.Sum256(got)
	return subtle.ConstantTimeCompare(want[:], d[:]) == 1
}
