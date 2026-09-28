package rawtls

import (
	"errors"
	"fmt"
	"hash/crc32"
	"path/filepath"
	"runtime"
	"strings"
)

type (
	ClientSide struct {
		Emitter
		Iterator
	}

	ClientHello struct {
		Record    BytesRange
		Handshake BytesRange

		Random       BytesRange
		Session      BytesRange
		CipherSuites BytesRange
		Compression  BytesRange
		Extensions   BytesRange

		RecordLegacyVersion ProtocolVersion
		HelloLegacyVersion  ProtocolVersion

		ServerName          BytesRange
		SupportedGroups     BytesRange // list of KeyGroup
		SignatureAlgorithms BytesRange // list of SignatureScheme
		ALPN                BytesRange // ProtocolNameList
		Cookie              BytesRange

		Exts     []Ext
		Versions []ProtocolVersion
		KeyShare []Key

		extsbuf [4]Ext
		keysbuf [4]Key
		versbuf [4]ProtocolVersion
	}
)

// ParseHello parses TLS ClientHello record.
// The record must contain exactly one complete message.
//
// Based on:
//
//	RFC8446: The Transport Layer Security (TLS) Protocol Version 1.3
//	https://datatracker.ietf.org/doc/html/rfc8446#autoid-21
func (c ClientSide) ParseHello(b []byte, m *ClientHello) (i int, err error) {
	// defer func() {
	// 	fmt.Printf("parse client hello  %x, %v  from %v\n", i, err, caller(1))
	// }()

	m.Record, i, err = parseHandshakeRecord(b, 0, &m.RecordLegacyVersion)
	if err != nil {
		return i, err
	}

	i, err = c.ParseHelloMessage(b[:m.Record.End()], i, m)

	return helloRecordEnd(m.Record, i, err)
}

// ParseHelloMessage parses ClientHello handshake message at st.
// Record is left as is.
func (c ClientSide) ParseHelloMessage(b []byte, st int, m *ClientHello) (i int, err error) {
	m.Handshake, i, err = parseMessage(b, st, MsgClientHello)
	if err != nil {
		return i, err
	}

	end := m.Handshake.End()

	if i+40 > end {
		return i, ErrMalformed
	}

	m.HelloLegacyVersion = u16[ProtocolVersion](b, &i)

	m.Random = br(i, i+32)
	i += 32

	// each check reserves the next field length prefix too, it's read before it's checked

	l := u8[int](b, &i) // session
	if i+l+2 > end {
		return i, ErrMalformed
	}

	m.Session = br(i, i+l)
	i += l

	l = u16[int](b, &i) // cipher suites
	if i+l+1 > end {
		return i, ErrMalformed
	}

	m.CipherSuites = br(i, i+l)
	i += l

	l = u8[int](b, &i) // legacy compression algs
	if i+l+2 > end {
		return i, ErrMalformed
	}

	m.Compression = br(i, i+l)
	i += l

	l = u16[int](b, &i) // extensions
	if i+l > end {
		return i, ErrMalformed
	}

	m.Extensions = br(i, i+l)
	if m.Extensions.E != m.Handshake.E {
		return i, ErrMalformed
	}

	m.softResetExts()

	m.Exts, i, err = parseExts(b, i, m.Extensions.End(), m.parseExt, m.Exts)

	return i, err
}

// OpenHello starts ClientHello message: the header and the fields before extensions.
// Extensions are appended then, and the message is finished with CloseHello.
//
//	b, hs, ext := c.OpenHello(b, random, session, TLS_AES_128_GCM_SHA256)
//	b = c.AppendExtServerName(b, host)
//	b = c.CloseHello(b, hs, ext)
func (c ClientSide) OpenHello(b, random, session []byte, suites ...CipherSuite) (_ []byte, hs, ext int) {
	if len(random) != 32 {
		panic(len(random))
	}

	b, hs = c.OpenHandshake(b, MsgClientHello)

	b = appendU16(b, VerTLS12)
	b = append(b, random...)

	b, st := c.OpenLen8(b)
	b = append(b, session...)
	b = c.CloseLen8(b, st)

	b, st = c.OpenLen16(b)

	for _, s := range suites {
		b = appendU16(b, s)
	}

	b = c.CloseLen16(b, st)

	b, st = c.OpenLen8(b)
	b = appendU8(b, 0) // null compression
	b = c.CloseLen8(b, st)

	b, ext = c.OpenLen16(b)

	return b, hs, ext
}

func (c ClientSide) CloseHello(b []byte, hs, ext int) []byte {
	b = c.CloseLen16(b, ext)

	return c.CloseHandshake(b, hs)
}

// AppendHello appends TLS ClientHello message m to the buffer b.
// Variable length values are copied from src, the buffer m was parsed from.
func (c ClientSide) AppendHello(b []byte, m *ClientHello, src []byte) []byte {
	b, rec := c.OpenRecord(b, RecHandshake, m.RecordLegacyVersion)
	b, hs := c.OpenHandshake(b, MsgClientHello)

	b = appendU16(b, m.HelloLegacyVersion)
	b = append(b, m.Random.Data(src)...)

	b, st := c.OpenLen8(b) // session
	b = append(b, m.Session.Data(src)...)
	b = c.CloseLen8(b, st)

	b, st = c.OpenLen16(b) // cipher suites
	b = append(b, m.CipherSuites.Data(src)...)
	b = c.CloseLen16(b, st)

	b, st = c.OpenLen8(b) // legacy compression algs
	b = append(b, m.Compression.Data(src)...)
	b = c.CloseLen8(b, st)

	b, st = c.OpenLen16(b) // extensions

	for _, x := range m.Exts {
		b = c.AppendExt(b, src, x)
	}

	b = c.CloseLen16(b, st)

	b = c.CloseHandshake(b, hs)
	b = c.CloseRecord(b, rec)

	return b
}

func (m *ClientHello) parseExt(b []byte, e Ext) error {
	i := e.Start()

	switch e.Type {
	case ExtServerName:
		if e.Length < 2 {
			return ErrMalformed
		}

		l := u16[int](b, &i)
		if i+l != e.End() || l < 1 {
			return ErrMalformed
		}

		for end := i + l; i < end; {
			if i+3 > end {
				return ErrMalformed
			}

			tp := u8[NameType](b, &i)
			l := u16[int](b, &i)
			if i+l > end {
				return ErrMalformed
			}

			if tp == NameHostName {
				m.ServerName = br(i, i+l)
			}

			i += l
		}
	case ExtSupportedVersions:
		if e.Length < 1 {
			return ErrMalformed
		}

		l := u8[int](b, &i)
		if i+l != e.End() || l&1 == 1 {
			return ErrMalformed
		}

		for end := i + l; i < end; {
			ver := u16[ProtocolVersion](b, &i)

			m.Versions = append(m.Versions, ver)
		}
	case ExtSupportedGroups, ExtSignatureAlgorithms:
		r, err := parseList16(b, e)
		if err != nil {
			return err
		}

		if e.Type == ExtSupportedGroups {
			m.SupportedGroups = r
		} else {
			m.SignatureAlgorithms = r
		}
	case ExtALPN:
		r, err := parseALPN(b, e)
		if err != nil {
			return err
		}

		m.ALPN = r
	case ExtCookie:
		r, err := parseCookie(b, e)
		if err != nil {
			return err
		}

		m.Cookie = r
	case ExtKeyShare:
		if e.Length < 2 {
			return ErrMalformed
		}

		l := u16[int](b, &i)
		if i+l != e.End() {
			return ErrMalformed
		}

		for end := i + l; i < end; {
			if i+4 > end {
				return ErrMalformed
			}

			var k Key

			k.Group = u16[KeyGroup](b, &i)
			k.Length = u16[uint16](b, &i)
			k.Offset = uint16(i)

			if i+int(k.Length) > end {
				return ErrMalformed
			}

			i = k.End()
			m.KeyShare = append(m.KeyShare, k)
		}
	}

	return nil
}

func parseExts(b []byte, st, end int, extf func(b []byte, e Ext) error, exts []Ext) (_ []Ext, i int, err error) {
	// defer func() {
	// 	fmt.Printf("parse extensions    %x, %v  from %v\n", i, err, caller(1))
	// }()

	for i = st; i < end; {
		if i+4 > end {
			return exts, i, ErrMalformed
		}

		var e Ext

		e.Type = u16[ExtensionType](b, &i)
		e.Length = u16[uint16](b, &i)
		e.Offset = uint16(i)

		if e.End() > end {
			return exts, i, ErrMalformed
		}

		exts = append(exts, e)

		if extf != nil {
			err = extf(b, e)
			if err != nil {
				return exts, i, err
			}
		}

		i = e.End()
	}

	return exts, i, nil
}

// parseHandshakeRecord parses handshake record header at st
// and checks the whole record is in b.
func parseHandshakeRecord(b []byte, st int, ver *ProtocolVersion) (rec BytesRange, i int, err error) {
	var d Iterator

	tp, v, l, i, err := d.RecordHeader(b, st)
	if err != nil {
		return rec, i, err
	}
	if tp != RecHandshake {
		return rec, st, ErrUnexpected
	}

	*ver = v

	rec = br(i, i+l)

	if i+l > len(b) {
		return rec, i, ErrShortBuffer
	}

	return rec, i, nil
}

// helloRecordEnd converts the hello message parse result into the record parse result.
// The message must fill the record exactly.
func helloRecordEnd(rec BytesRange, i int, err error) (int, error) {
	if errors.Is(err, ErrShortBuffer) { // the message continues in the next record
		return i, ErrFragmented
	}
	if err != nil {
		return i, err
	}

	if i != rec.End() {
		return i, ErrMalformed
	}

	return i, nil
}

// parseMessage parses handshake message header of type msg at st.
// It returns the message body range.
func parseMessage(b []byte, st int, msg HandshakeType) (hs BytesRange, i int, err error) {
	var d Iterator

	body, i, err := d.Message(b, st, msg)
	if err != nil {
		return hs, i, err
	}

	if i > 0xffff { // ranges are uint16
		return hs, st, ErrMalformed
	}

	return br(i-len(body), i), i - len(body), nil
}

// parseList16 parses extension data which is a non-empty list of 16-bit values.
// It returns the list range.
func parseList16(b []byte, e Ext) (BytesRange, error) {
	i := e.Start()

	if e.Length < 2 {
		return zeroRange, ErrMalformed
	}

	l := u16[int](b, &i)
	if i+l != e.End() || l == 0 || l&1 == 1 {
		return zeroRange, ErrMalformed
	}

	return br(i, i+l), nil
}

// parseALPN parses application_layer_protocol_negotiation extension data.
// It returns the ProtocolNameList range.
//
//	RFC7301: https://datatracker.ietf.org/doc/html/rfc7301#section-3.1
func parseALPN(b []byte, e Ext) (BytesRange, error) {
	i := e.Start()

	if e.Length < 2 {
		return zeroRange, ErrMalformed
	}

	l := u16[int](b, &i)
	if i+l != e.End() || l == 0 {
		return zeroRange, ErrMalformed
	}

	r := br(i, i+l)

	for i < r.End() {
		l := u8[int](b, &i)
		if l == 0 || i+l > r.End() {
			return zeroRange, ErrMalformed
		}

		i += l
	}

	return r, nil
}

// parseCookie parses cookie extension data.
// It returns the cookie range.
func parseCookie(b []byte, e Ext) (BytesRange, error) {
	i := e.Start()

	if e.Length < 2 {
		return zeroRange, ErrMalformed
	}

	l := u16[int](b, &i)
	if i+l != e.End() || l == 0 {
		return zeroRange, ErrMalformed
	}

	return br(i, i+l), nil
}

func (m *ClientHello) softResetExts() {
	if m.Exts == nil {
		m.Exts = m.extsbuf[:0]
	} else {
		m.Exts = m.Exts[:0]
	}

	if m.KeyShare == nil {
		m.KeyShare = m.keysbuf[:0]
	} else {
		m.KeyShare = m.KeyShare[:0]
	}

	if m.Versions == nil {
		m.Versions = m.versbuf[:0]
	} else {
		m.Versions = m.Versions[:0]
	}

	m.ServerName = zeroRange
	m.SupportedGroups = zeroRange
	m.SignatureAlgorithms = zeroRange
	m.ALPN = zeroRange
	m.Cookie = zeroRange
}

func (m *ClientHello) Dump(buf []byte) string {
	var b strings.Builder
	var cip []CipherSuite

	var sess uint32
	if len(buf) != 0 && !m.Session.IsZero() {
		sess = crc32.ChecksumIEEE(m.Session.Data(buf))
	}

	if len(buf) != 0 {
		data := m.CipherSuites.Data(buf)
		cip = make([]CipherSuite, len(data)/2)

		for i := range cip {
			j := 2 * i
			cip[i] = u16[CipherSuite](data, &j)
		}
	}

	fmt.Fprintf(&b, "client hello  %4x %4x\n", m.Record.S, m.Record.E)
	fmt.Fprintf(&b, "handshake     %4x %4x\n", m.Handshake.S, m.Handshake.E)
	fmt.Fprintf(&b, "random        %4x %4x\n", m.Random.S, m.Random.E)
	fmt.Fprintf(&b, "session       %4x %4x    %08x\n", m.Session.S, m.Session.E, sess)
	fmt.Fprintf(&b, "cipher        %4x %4x    %04x\n", m.CipherSuites.S, m.CipherSuites.E, cip)
	fmt.Fprintf(&b, "compress      %4x %4x\n", m.Compression.S, m.Compression.E)
	fmt.Fprintf(&b, "extensions    %4x %4x\n", m.Extensions.S, m.Extensions.E)

	fmt.Fprintf(&b, "version leg   %04x %04x\n", m.RecordLegacyVersion, m.HelloLegacyVersion)

	if !m.ServerName.IsZero() {
		fmt.Fprintf(&b, "    server    %4x %4x", m.ServerName.S, m.ServerName.E)

		if len(buf) != 0 {
			fmt.Fprintf(&b, "  %q\n", m.ServerName.Data(buf))
		} else {
			b.WriteByte('\n')
		}
	}

	if len(m.Versions) != 0 {
		fmt.Fprintf(&b, "    versions ")

		for _, ver := range m.Versions {
			fmt.Fprintf(&b, " %04x", ver)
		}

		b.WriteByte('\n')
	}

	for _, ext := range m.Exts {
		ext.dump(&b, buf)
	}

	for _, key := range m.KeyShare {
		key.dump(&b, buf)
	}

	return b.String()
}

func (e Ext) dump(b *strings.Builder, buf []byte) {
	fmt.Fprintf(b, "    ext       %4x %4x %4x", e.Type, e.Length, e.Offset)

	switch {
	case len(buf) == 0:
	case e.Length <= 0x10:
		fmt.Fprintf(b, "    % 2x", e.Data(buf))
	default:
		fmt.Fprintf(b, "    %08x", crc32.ChecksumIEEE(e.Data(buf)))
	}

	b.WriteByte('\n')
}

func (k Key) dump(b *strings.Builder, buf []byte) {
	fmt.Fprintf(b, "    key       %4x %4x %4x", k.Group, k.Length, k.Offset)

	switch {
	case len(buf) == 0:
	case k.Length <= 0x10:
		fmt.Fprintf(b, "    % 2x", k.Data(buf))
	default:
		fmt.Fprintf(b, "    %08x", crc32.ChecksumIEEE(k.Data(buf)))
	}

	b.WriteByte('\n')
}

func br(st, end int) BytesRange {
	return BytesRange{S: uint16(st), E: uint16(end)}
}

func (r BytesRange) Start() int           { return int(r.S) }
func (r BytesRange) End() int             { return int(r.E) }
func (r BytesRange) Len() int             { return int(r.E - r.S) }
func (r BytesRange) IsZero() bool         { return r == BytesRange{} }
func (r BytesRange) Data(b []byte) []byte { return b[r.S:r.E] }

func (e Ext) Start() int           { return int(e.Offset) }
func (e Ext) End() int             { return int(e.Offset) + int(e.Length) }
func (e Ext) IsZero() bool         { return e == Ext{} }
func (e Ext) Data(b []byte) []byte { return b[e.Start():e.End()] }
func (k Key) Start() int           { return int(k.Offset) }
func (k Key) End() int             { return int(k.Offset) + int(k.Length) }
func (k Key) IsZero() bool         { return k == Key{} }
func (k Key) Data(b []byte) []byte { return b[k.Start():k.End()] }

//nolint:unused // used by the commented out debug lines
func caller(d int) string {
	_, file, line, _ := runtime.Caller(1 + d)

	return fmt.Sprintf("%v:%v", filepath.Base(file), line)
}
