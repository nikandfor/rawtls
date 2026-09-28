package rawtls

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestIteratorShortBuffer(t *testing.T) {
	var d Iterator

	b := []byte{0xff, byte(RecHandshake), 3, 3, 0, 10}

	_, _, _, i, err := d.RecordHeader(b[:5], 1)
	if !errors.Is(err, ErrShortBuffer) || i != 1 {
		t.Errorf("record header: %d %v, wanted 1 %v", i, err, ErrShortBuffer)
	}

	tp, ver, l, i, err := d.RecordHeader(b, 1)
	if err != nil || tp != RecHandshake || ver != VerTLS12 || l != 10 || i != 6 {
		t.Errorf("record header: %x %x %d %d %v", tp, ver, l, i, err)
	}

	b = []byte{0xff, byte(MsgKeyUpdate), 0, 0, 1}

	_, _, i, err = d.HandshakeHeader(b[:4], 1)
	if !errors.Is(err, ErrShortBuffer) || i != 1 {
		t.Errorf("handshake header: %d %v, wanted 1 %v", i, err, ErrShortBuffer)
	}

	msg, l, i, err := d.HandshakeHeader(b, 1)
	if err != nil || msg != MsgKeyUpdate || l != 1 || i != 5 {
		t.Errorf("handshake header: %x %d %d %v", msg, l, i, err)
	}
}

func TestHandshakeMessage(t *testing.T) {
	var d Iterator

	msg := []byte{byte(MsgKeyUpdate), 0, 0, 5, 1, 2, 3, 4, 5}

	for _, step := range []int{1, 2, 3, 4, 5, 8, 9} {
		b := append([]byte{0xff}, fragment(RecHandshake, VerTLS12, msg, step)...)
		b = append(b, 0xee) // the next record

		orig := bytes.Clone(b)

		m, ver, i, err := d.HandshakeMessage([]byte{0xdd}, b, 1)
		if err != nil || ver != VerTLS12 || i != len(b)-1 || !bytes.Equal(m, append([]byte{0xdd}, msg...)) {
			t.Errorf("step %d: %x %x %d/%d %v", step, m, ver, i, len(b), err)
		}
		if !bytes.Equal(b, orig) {
			t.Errorf("step %d: input modified", step)
		}

		_, _, i, err = d.HandshakeMessage(nil, b[:len(b)-2], 1)
		if !errors.Is(err, ErrShortBuffer) || i != 1 {
			t.Errorf("step %d: short: %d %v", step, i, err)
		}
	}

	for _, tc := range []struct {
		name string
		b    []byte
		err  error
	}{
		{"interleaved", slices.Concat(fragment(RecHandshake, VerTLS12, msg[:3], 3), []byte{byte(RecChangeCipherSpec), 3, 3, 0, 1, 1}, fragment(RecHandshake, VerTLS12, msg[3:], 9)), ErrUnexpected},
		{"empty", slices.Concat(fragment(RecHandshake, VerTLS12, msg[:3], 3), []byte{byte(RecHandshake), 3, 3, 0, 0}, fragment(RecHandshake, VerTLS12, msg[3:], 9)), ErrMalformed},
		{"not_ending_record", fragment(RecHandshake, VerTLS12, slices.Concat(msg, []byte{byte(MsgKeyUpdate)}), 5), ErrMalformed},
		{"too_long", fragment(RecHandshake, VerTLS12, []byte{byte(MsgCertificate), 1, 0, 1}, 4), ErrMalformed},
		{"record_too_long", []byte{byte(RecHandshake), 3, 3, 0x40, 1}, ErrMalformed},
		{"not_handshake", fragment(RecAlert, VerTLS12, msg, 9), ErrUnexpected},
	} {
		m, _, i, err := d.HandshakeMessage([]byte{0xdd}, tc.b, 0)
		if !errors.Is(err, tc.err) || i != 0 || !bytes.Equal(m, []byte{0xdd}) {
			t.Errorf("%s: %x %d %v, wanted %v", tc.name, m, i, err, tc.err)
		}
	}
}

// fragment splits msg into records of step bytes.
func fragment(tp ContentType, ver ProtocolVersion, msg []byte, step int) (b []byte) {
	var e Emitter

	for i := 0; i < len(msg); i += step {
		var st int

		b, st = e.OpenRecord(b, tp, ver)
		b = append(b, msg[i:min(i+step, len(msg))]...)
		b = e.CloseRecord(b, st)
	}

	return b
}
