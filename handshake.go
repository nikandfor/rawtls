package rawtls

type (
	EncryptedExtensions struct {
		Handshake  BytesRange
		Extensions BytesRange

		ALPN BytesRange // selected protocol

		Exts []Ext

		extsbuf [4]Ext
	}
)

// ParseEncryptedExtensions parses EncryptedExtensions handshake message at st.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
func (s ServerSide) ParseEncryptedExtensions(b []byte, st int, m *EncryptedExtensions) (i int, err error) {
	m.Handshake, i, err = parseMessage(b, st, MsgEncryptedExtensions)
	if err != nil {
		return i, err
	}

	if i+2 > m.Handshake.End() {
		return i, ErrMalformed
	}

	l := u16[int](b, &i)
	if i+l != m.Handshake.End() {
		return i, ErrMalformed
	}

	m.Extensions = br(i, i+l)
	m.ALPN = zeroRange

	if m.Exts == nil {
		m.Exts = m.extsbuf[:0]
	} else {
		m.Exts = m.Exts[:0]
	}

	m.Exts, i, err = parseExts(b, i, m.Extensions.End(), m.parseExt, m.Exts)

	return i, err
}

// OpenEncryptedExtensions starts EncryptedExtensions message.
// Extensions are appended then, and the message is finished with CloseEncryptedExtensions.
func (s ServerSide) OpenEncryptedExtensions(b []byte) (_ []byte, hs, ext int) {
	b, hs = s.OpenHandshake(b, MsgEncryptedExtensions)
	b, ext = s.OpenLen16(b)

	return b, hs, ext
}

func (s ServerSide) CloseEncryptedExtensions(b []byte, hs, ext int) []byte {
	b = s.CloseLen16(b, ext)

	return s.CloseHandshake(b, hs)
}

func (m *EncryptedExtensions) parseExt(b []byte, e Ext) error {
	if e.Type != ExtALPN {
		return nil
	}

	r, err := parseALPN(b, e)
	if err != nil {
		return err
	}

	i := r.Start()
	l := u8[int](b, &i)

	if i+l != r.End() { // exactly one protocol is selected
		return ErrMalformed
	}

	m.ALPN = br(i, i+l)

	return nil
}

// AppendCertificate appends Certificate message with the certificate chain.
// Certificate entries have no extensions.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
func (e Emitter) AppendCertificate(b, context []byte, chain ...[]byte) []byte {
	b, hs := e.OpenHandshake(b, MsgCertificate)

	b, st := e.OpenLen8(b)
	b = append(b, context...)
	b = e.CloseLen8(b, st)

	b, list := e.OpenLen24(b)

	for _, cert := range chain {
		b, st = e.OpenLen24(b)
		b = append(b, cert...)
		b = e.CloseLen24(b, st)

		b = appendU16(b, 0) // no entry extensions
	}

	b = e.CloseLen24(b, list)

	return e.CloseHandshake(b, hs)
}

// AppendCertificateVerify appends CertificateVerify message.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
func (e Emitter) AppendCertificateVerify(b []byte, scheme SignatureScheme, sig []byte) []byte {
	b, hs := e.OpenHandshake(b, MsgCertificateVerify)

	b = appendU16(b, scheme)

	b, st := e.OpenLen16(b)
	b = append(b, sig...)
	b = e.CloseLen16(b, st)

	return e.CloseHandshake(b, hs)
}

// AppendFinished appends Finished message.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
func (e Emitter) AppendFinished(b, verify []byte) []byte {
	b, hs := e.OpenHandshake(b, MsgFinished)
	b = append(b, verify...)

	return e.CloseHandshake(b, hs)
}

// Certificate parses Certificate message at st.
// It returns certificate request context and the certificate entry list to walk with CertificateEntry.
func (d Iterator) Certificate(b []byte, st int) (context, list []byte, i int, err error) {
	body, i, err := d.Message(b, st, MsgCertificate)
	if err != nil {
		return nil, nil, st, err
	}

	j := 0

	if j+1 > len(body) {
		return nil, nil, st, ErrMalformed
	}

	l := u8[int](body, &j)
	if j+l+3 > len(body) {
		return nil, nil, st, ErrMalformed
	}

	context = body[j : j+l]
	j += l

	l = u24[int](body, &j)
	if j+l != len(body) {
		return nil, nil, st, ErrMalformed
	}

	return context, body[j:], i, nil
}

// CertificateEntry parses certificate entry at st of the list.
// It returns the certificate data and the next entry position.
// Entry extensions are skipped.
func (d Iterator) CertificateEntry(list []byte, st int) (cert []byte, i int, err error) {
	i = st

	if i+3 > len(list) {
		return nil, st, ErrMalformed
	}

	l := u24[int](list, &i)
	if l == 0 || i+l+2 > len(list) {
		return nil, st, ErrMalformed
	}

	cert = list[i : i+l]
	i += l

	l = u16[int](list, &i)
	if i+l > len(list) {
		return nil, st, ErrMalformed
	}

	i += l

	return cert, i, nil
}

// CertificateVerify parses CertificateVerify message at st.
func (d Iterator) CertificateVerify(b []byte, st int) (scheme SignatureScheme, sig []byte, i int, err error) {
	body, i, err := d.Message(b, st, MsgCertificateVerify)
	if err != nil {
		return 0, nil, st, err
	}

	j := 0

	if j+4 > len(body) {
		return 0, nil, st, ErrMalformed
	}

	scheme = u16[SignatureScheme](body, &j)
	l := u16[int](body, &j)

	if j+l != len(body) {
		return 0, nil, st, ErrMalformed
	}

	return scheme, body[j:], i, nil
}

// Finished parses Finished message at st. It returns verify_data.
func (d Iterator) Finished(b []byte, st int) (verify []byte, i int, err error) {
	return d.Message(b, st, MsgFinished)
}
