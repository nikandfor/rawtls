package rawtls

type (
	Iterator struct{}
)

// RecordHeader parses the record header at st.
// It returns content type, legacy version, fragment length and the fragment start.
// The fragment itself may be not in b yet.
func (d Iterator) RecordHeader(b []byte, st int) (tp ContentType, ver ProtocolVersion, l, i int, err error) {
	i = st

	if i+5 > len(b) {
		return 0, 0, 0, st, ErrShortBuffer
	}

	tp = u8[ContentType](b, &i)
	ver = u16[ProtocolVersion](b, &i)
	l = u16[int](b, &i)

	return tp, ver, l, i, nil
}

// HandshakeHeader parses the handshake message header at st.
// It returns message type, body length and the body start.
// The body itself may be not in b yet.
func (d Iterator) HandshakeHeader(b []byte, st int) (msg HandshakeType, l, i int, err error) {
	i = st

	if i+4 > len(b) {
		return 0, 0, st, ErrShortBuffer
	}

	msg = u8[HandshakeType](b, &i)
	l = u24[int](b, &i)

	return msg, l, i, nil
}

// Message parses the handshake message of type msg at st.
// It returns the message body and the position after the message.
func (d Iterator) Message(b []byte, st int, msg HandshakeType) (body []byte, i int, err error) {
	tp, l, i, err := d.HandshakeHeader(b, st)
	if err != nil {
		return nil, st, err
	}
	if tp != msg {
		return nil, st, ErrUnexpected
	}
	if i+l > len(b) {
		return nil, st, ErrShortBuffer
	}

	return b[i : i+l], i + l, nil
}

// HandshakeMessage reassembles a handshake message fragmented over plaintext handshake records.
// It appends record fragments from b starting at st to dst until they make a complete message,
// which must end its record, and returns dst, the version of the first record,
// and the position after the last record. The message starts at the initial len(dst).
// b is not modified. ErrShortBuffer means more records are needed.
func (d Iterator) HandshakeMessage(dst, b []byte, st int) (_ []byte, ver ProtocolVersion, i int, err error) {
	m := len(dst)
	i = st

	for {
		tp, v, l, fst, err := d.RecordHeader(b, i)
		if err != nil {
			return dst[:m], 0, st, err
		}
		if tp != RecHandshake { // not interleaved with other records
			return dst[:m], 0, st, ErrUnexpected
		}
		if l == 0 || l > MaxPlaintext {
			return dst[:m], 0, st, ErrMalformed
		}
		if fst+l > len(b) {
			return dst[:m], 0, st, ErrShortBuffer
		}
		if i == st {
			ver = v
		}

		dst = append(dst, b[fst:fst+l]...)
		i = fst + l

		_, ml, hst, err := d.HandshakeHeader(dst, m)
		if err != nil { // the header is split
			continue
		}
		if ml > MaxHandshake {
			return dst[:m], 0, st, ErrMalformed
		}
		if hst+ml > len(dst) {
			continue
		}
		if hst+ml < len(dst) {
			return dst[:m], 0, st, ErrMalformed
		}

		return dst, ver, i, nil
	}
}

// list16 decodes a list of 16-bit values.
func list16[T ints16](b []byte) (r []T) {
	for i := 0; i+2 <= len(b); {
		r = append(r, u16[T](b, &i))
	}

	return r
}

func u8[T ints](b []byte, i *int) T {
	r := T(b[*i])
	*i++
	return r
}

func u16[T ints16](b []byte, i *int) T {
	r := T(b[*i])<<8 + T(b[*i+1])
	*i += 2
	return r
}

func u24[T ints32](b []byte, i *int) T {
	r := T(b[*i])<<16 + T(b[*i+1])<<8 + T(b[*i+2])
	*i += 3
	return r
}
