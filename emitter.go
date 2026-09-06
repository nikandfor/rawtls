package rawtls

import "slices"

type (
	Emitter struct{}
)

func (e Emitter) OpenRecord(b []byte, tp ContentType, ver ProtocolVersion) ([]byte, int) {
	b = appendU8(b, tp)
	b = appendU16(b, ver)

	return e.OpenLen16(b)
}

func (e Emitter) CloseRecord(b []byte, st int) []byte { return e.CloseLen16(b, st) }

func (e Emitter) OpenHandshake(b []byte, msg HandshakeType) ([]byte, int) {
	b = appendU8(b, msg)

	return e.OpenLen24(b)
}

func (e Emitter) CloseHandshake(b []byte, st int) []byte { return e.CloseLen24(b, st) }

func (e Emitter) AppendExt(b, src []byte, x Ext) []byte {
	b = appendU16(b, x.Type)
	b = appendU16(b, x.Length)

	return append(b, x.Data(src)...)
}

// AppendExtServerName appends server_name extension with a single host_name.
//
//	RFC6066: Transport Layer Security (TLS) Extensions: Extension Definitions
//	https://datatracker.ietf.org/doc/html/rfc6066#section-3
func (e Emitter) AppendExtServerName(b []byte, host string) []byte {
	b = appendU16(b, ExtServerName)

	b, ext := e.OpenLen16(b)
	b, list := e.OpenLen16(b)

	b = appendU8(b, NameHostName)

	b, name := e.OpenLen16(b)
	b = append(b, host...)
	b = e.CloseLen16(b, name)

	b = e.CloseLen16(b, list)

	return e.CloseLen16(b, ext)
}

// AppendExtPadding appends padding extension of n zero bytes.
//
//	RFC7685: A Transport Layer Security (TLS) ClientHello Padding Extension
//	https://datatracker.ietf.org/doc/html/rfc7685
func (e Emitter) AppendExtPadding(b []byte, n int) []byte {
	if n < 0 || n > 0xffff {
		panic(n)
	}

	b = appendU16(b, ExtPadding)
	b = appendU16(b, n)

	b = slices.Grow(b, n)
	b = b[:len(b)+n]

	clear(b[len(b)-n:])

	return b
}

// OpenLen8 appends a placeholder for the length prefix and returns
// the value start position to pass to CloseLen8, which fills the placeholder in.
//
//	b, st := e.OpenLen8(b)
//	b = append(b, ...) // arbitrary value of arbitrary size
//	b = e.CloseLen8(b, st)
func (e Emitter) OpenLen8(b []byte) ([]byte, int)  { return append(b, 0), len(b) + 1 }
func (e Emitter) OpenLen16(b []byte) ([]byte, int) { return append(b, 0, 0), len(b) + 2 }
func (e Emitter) OpenLen24(b []byte) ([]byte, int) { return append(b, 0, 0, 0), len(b) + 3 }

func (e Emitter) CloseLen8(b []byte, st int) []byte {
	l := len(b) - st
	if l > 0xff {
		panic(l)
	}

	b[st-1] = byte(l)

	return b
}

func (e Emitter) CloseLen16(b []byte, st int) []byte {
	l := len(b) - st
	if l > 0xffff {
		panic(l)
	}

	b[st-2] = byte(l >> 8)
	b[st-1] = byte(l)

	return b
}

func (e Emitter) CloseLen24(b []byte, st int) []byte {
	l := len(b) - st
	if l > 0xff_ffff {
		panic(l)
	}

	b[st-3] = byte(l >> 16)
	b[st-2] = byte(l >> 8)
	b[st-1] = byte(l)

	return b
}

func appendU8[T ints](b []byte, v T) []byte    { return append(b, byte(v)) }
func appendU16[T ints16](b []byte, v T) []byte { return append(b, byte(v>>8), byte(v)) }
