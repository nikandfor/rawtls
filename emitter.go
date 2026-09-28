package rawtls

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

// OpenExt starts extension of type tp. The data is appended then,
// and the extension is finished with CloseExt.
func (e Emitter) OpenExt(b []byte, tp ExtensionType) ([]byte, int) {
	b = appendU16(b, tp)

	return e.OpenLen16(b)
}

func (e Emitter) CloseExt(b []byte, st int) []byte { return e.CloseLen16(b, st) }

// AppendExtServerName appends server_name extension with a single host_name.
//
//	RFC6066: Transport Layer Security (TLS) Extensions: Extension Definitions
//	https://datatracker.ietf.org/doc/html/rfc6066#section-3
func (e Emitter) AppendExtServerName(b []byte, host string) []byte {
	b, ext := e.OpenExt(b, ExtServerName)
	b, list := e.OpenLen16(b)

	b = appendU8(b, NameHostName)

	b, name := e.OpenLen16(b)
	b = append(b, host...)
	b = e.CloseLen16(b, name)

	b = e.CloseLen16(b, list)

	return e.CloseExt(b, ext)
}

// AppendExtSupportedVersions appends supported_versions extension in the ClientHello form.
// ServerHello carries a single version with no list length.
func (e Emitter) AppendExtSupportedVersions(b []byte, vers ...ProtocolVersion) []byte {
	b, ext := e.OpenExt(b, ExtSupportedVersions)
	b, st := e.OpenLen8(b)

	for _, v := range vers {
		b = appendU16(b, v)
	}

	b = e.CloseLen8(b, st)

	return e.CloseExt(b, ext)
}

func (e Emitter) AppendExtSupportedGroups(b []byte, groups ...KeyGroup) []byte {
	b, ext := e.OpenExt(b, ExtSupportedGroups)
	b, st := e.OpenLen16(b)

	for _, g := range groups {
		b = appendU16(b, g)
	}

	b = e.CloseLen16(b, st)

	return e.CloseExt(b, ext)
}

func (e Emitter) AppendExtSignatureAlgorithms(b []byte, schemes ...SignatureScheme) []byte {
	b, ext := e.OpenExt(b, ExtSignatureAlgorithms)
	b, st := e.OpenLen16(b)

	for _, s := range schemes {
		b = appendU16(b, s)
	}

	b = e.CloseLen16(b, st)

	return e.CloseExt(b, ext)
}

// AppendExtALPN appends application_layer_protocol_negotiation extension.
// ServerHello carries exactly one protocol.
//
//	RFC7301: https://datatracker.ietf.org/doc/html/rfc7301#section-3.1
func (e Emitter) AppendExtALPN(b []byte, protos ...string) []byte {
	b, ext := e.OpenExt(b, ExtALPN)
	b, list := e.OpenLen16(b)

	var st int

	for _, p := range protos {
		b, st = e.OpenLen8(b)
		b = append(b, p...)
		b = e.CloseLen8(b, st)
	}

	b = e.CloseLen16(b, list)

	return e.CloseExt(b, ext)
}

// AppendKeyShareEntry appends key_share entry.
// ClientHello has a list of them, ServerHello has one.
func (e Emitter) AppendKeyShareEntry(b []byte, group KeyGroup, key []byte) []byte {
	b = appendU16(b, group)

	b, st := e.OpenLen16(b)
	b = append(b, key...)

	return e.CloseLen16(b, st)
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

	return appendZeros(b, n)
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
	e.SetLen8(b, st, len(b)-st)

	return b
}

func (e Emitter) CloseLen16(b []byte, st int) []byte {
	e.SetLen16(b, st, len(b)-st)

	return b
}

func (e Emitter) CloseLen24(b []byte, st int) []byte {
	e.SetLen24(b, st, len(b)-st)

	return b
}

// SetLen8 sets the length prefix of the value starting at st to l.
// Unlike CloseLen8 the value doesn't have to be in b yet.
func (e Emitter) SetLen8(b []byte, st, l int) {
	if l > 0xff {
		panic(l)
	}

	b[st-1] = byte(l)
}

func (e Emitter) SetLen16(b []byte, st, l int) {
	if l > 0xffff {
		panic(l)
	}

	b[st-2] = byte(l >> 8)
	b[st-1] = byte(l)
}

func (e Emitter) SetLen24(b []byte, st, l int) {
	if l > 0xff_ffff {
		panic(l)
	}

	b[st-3] = byte(l >> 16)
	b[st-2] = byte(l >> 8)
	b[st-1] = byte(l)
}

func appendZeros(b []byte, n int) []byte {
	return append(b, make([]byte, n)...)
}

func appendU8[T ints](b []byte, v T) []byte    { return append(b, byte(v)) }
func appendU16[T ints16](b []byte, v T) []byte { return append(b, byte(v>>8), byte(v)) }
