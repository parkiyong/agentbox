package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID generates a time-ordered, Crockford base32-encoded identifier with the given prefix
// (e.g., "ses_", "evt_", "apr_", "chk_").
func NewID(prefix string) string {
	var buf [16]byte
	ms := uint64(time.Now().UnixMilli())
	buf[0] = byte(ms >> 40)
	buf[1] = byte(ms >> 32)
	buf[2] = byte(ms >> 24)
	buf[3] = byte(ms >> 16)
	buf[4] = byte(ms >> 8)
	buf[5] = byte(ms)
	if _, err := rand.Read(buf[6:]); err != nil {
		// Fallback to monotonic time bits if crypto/rand ever fails.
		binary.BigEndian.PutUint64(buf[6:14], uint64(time.Now().UnixNano()))
	}

	var out strings.Builder
	out.Grow(len(prefix) + 16)
	out.WriteString(prefix)

	// Encode 10 bytes (80 bits) into 16 Crockford base32 characters for compact, sortable IDs.
	val := uint64(buf[0])<<32 | uint64(buf[1])<<24 | uint64(buf[2])<<16 | uint64(buf[3])<<8 | uint64(buf[4])
	for i := 7; i >= 0; i-- {
		out.WriteByte(crockfordAlphabet[(val>>uint(i*5))&0x1F])
	}
	randVal := uint64(buf[5])<<32 | uint64(buf[6])<<24 | uint64(buf[7])<<16 | uint64(buf[8])<<8 | uint64(buf[9])
	for i := 7; i >= 0; i-- {
		out.WriteByte(crockfordAlphabet[(randVal>>uint(i*5))&0x1F])
	}
	return out.String()
}

// NewNonce generates a cryptographically secure random hex nonce for ephemeral sandbox auth.
func NewNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session nonce: %w", err)
	}
	return fmt.Sprintf("abx_nonce_%x", b[:]), nil
}
