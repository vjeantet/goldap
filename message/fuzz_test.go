package message

import (
	"reflect"
	"testing"
)

// FuzzReadLDAPMessage feeds random bytes into the LDAP message parser.
// It catches panics, out-of-bounds accesses, and infinite loops.
// Seed corpus: testdata/fuzz/FuzzReadLDAPMessage/
func FuzzReadLDAPMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		bytes := Bytes{offset: 0, bytes: data}
		// We don't care whether parsing succeeds or returns an error.
		// We only care that it doesn't panic.
		ReadLDAPMessage(&bytes)
	})
}

// FuzzRoundTrip parses random bytes and, if parsing succeeds, writes the
// message back out and re-parses. The two parsed messages must be equal.
// This catches asymmetries between the reader and writer (like bug #1,
// where encoding of integers >= 128 was incorrect).
func FuzzRoundTrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse
		bytes1 := Bytes{offset: 0, bytes: data}
		msg1, err := ReadLDAPMessage(&bytes1)
		if err != nil {
			return // invalid input, nothing to round-trip
		}

		// Write back
		written, err := msg1.Write()
		if err != nil {
			t.Fatalf("Write failed after successful Read: %v", err)
		}

		// Re-parse
		bytes2 := Bytes{offset: 0, bytes: written.getBytes()}
		msg2, err := ReadLDAPMessage(&bytes2)
		if err != nil {
			t.Fatalf("Re-read failed after Write: %v\nOriginal bytes: %x\nWritten bytes:  %x", err, data, written.getBytes())
		}

		// Compare
		if !reflect.DeepEqual(msg1, msg2) {
			t.Errorf("Round-trip mismatch:\nOriginal bytes: %x\nWritten bytes:  %x\nParsed1: %+v\nParsed2: %+v", data, written.getBytes(), msg1, msg2)
		}
	})
}
