package rawtls

import (
	"fmt"
	"hash/crc32"
	"strings"
)

type (
	Server struct {
		Emitter
	}

	ServerHello struct {
		Record    BytesRange
		Handshake BytesRange

		Random     BytesRange
		Session    BytesRange
		Extensions BytesRange

		CipherSuiteOffset uint16
		CipherSuite       CipherSuite
		Compression       byte

		RecordLegacyVersion ProtocolVersion
		HelloLegacyVersion  ProtocolVersion

		Exts     []Ext
		Version  ProtocolVersion
		KeyShare Key

		extsbuf [4]Ext
	}
)

// ParseHello parses TLS ServerHello message.
//
// Based on:
//
//	RFC8446: The Transport Layer Security (TLS) Protocol Version 1.3
//	https://datatracker.ietf.org/doc/html/rfc8446#autoid-22
func (s Server) ParseHello(b []byte, m *ServerHello) (i int, err error) {
	// defer func() {
	// 	fmt.Printf("parse server hello  %x, %v  from %v\n", i, err, caller(1))
	// }()

	m.Record, m.Handshake, i, err = parseHandshakeHeader(b, 0, MsgServerHello, &m.RecordLegacyVersion)
	if err != nil {
		return i, err
	}

	// server hello

	if i+40 > m.Handshake.End() {
		return i, ErrMalformed
	}

	m.HelloLegacyVersion = u16[ProtocolVersion](b, &i)

	m.Random = br(i, i+32)
	i += 32

	// the check reserves cipher suite, compression and extensions length too,
	// they are read before they are checked

	l := u8[int](b, &i) // session
	if i+l+5 > m.Record.End() {
		return i, ErrMalformed
	}

	m.Session = br(i, i+l)
	i += l

	m.CipherSuiteOffset = uint16(i)
	m.CipherSuite = u16[CipherSuite](b, &i)

	m.Compression = u8[byte](b, &i)

	l = u16[int](b, &i) // extensions
	if i+l > m.Record.End() {
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

// AppendHello appends TLS ServerHello message m to the buffer b.
// Variable length values are copied from src, the buffer m was parsed from.
func (s Server) AppendHello(b []byte, m *ServerHello, src []byte) []byte {
	b, rec := s.OpenRecord(b, RecHandshake, m.RecordLegacyVersion)
	b, hs := s.OpenHandshake(b, MsgServerHello)

	b = appendU16(b, m.HelloLegacyVersion)
	b = append(b, m.Random.Data(src)...)

	b, st := s.OpenLen8(b) // session
	b = append(b, m.Session.Data(src)...)
	b = s.CloseLen8(b, st)

	b = appendU16(b, m.CipherSuite)
	b = appendU8(b, m.Compression)

	b, st = s.OpenLen16(b) // extensions

	for _, x := range m.Exts {
		b = s.AppendExt(b, src, x)
	}

	b = s.CloseLen16(b, st)

	b = s.CloseHandshake(b, hs)
	b = s.CloseRecord(b, rec)

	return b
}

func (m *ServerHello) parseExt(b []byte, e Ext) error {
	i := e.Start()

	switch e.Type {
	case ExtSupportedVersions: // negotiated version
		if e.Length != 2 {
			return ErrMalformed
		}

		m.Version = u16[ProtocolVersion](b, &i)
	case ExtKeyShare:
		if e.Length < 4 {
			return ErrMalformed
		}

		var k Key

		k.Group = u16[KeyGroup](b, &i)
		k.Length = u16[uint16](b, &i)
		k.Offset = uint16(i)

		if k.End() != e.End() {
			return ErrMalformed
		}

		m.KeyShare = k
	}

	return nil
}

func (m *ServerHello) softResetExts() {
	if m.Exts == nil {
		m.Exts = m.extsbuf[:0]
	} else {
		m.Exts = m.Exts[:0]
	}
}

func (m *ServerHello) Dump(buf []byte) string {
	var b strings.Builder

	var sess uint32
	if len(buf) != 0 && !m.Session.IsZero() {
		sess = crc32.ChecksumIEEE(m.Session.Data(buf))
	}

	fmt.Fprintf(&b, "server hello  %4x %4x\n", m.Record.S, m.Record.E)
	fmt.Fprintf(&b, "handshake     %4x %4x\n", m.Handshake.S, m.Handshake.E)
	fmt.Fprintf(&b, "random        %4x %4x\n", m.Random.S, m.Random.E)
	fmt.Fprintf(&b, "session       %4x %4x    %08x\n", m.Session.S, m.Session.E, sess)
	fmt.Fprintf(&b, "cipher        %4x         %04x\n", m.CipherSuiteOffset, m.CipherSuite)
	fmt.Fprintf(&b, "compress      %4x %4x\n", m.CipherSuiteOffset+2, m.Compression)
	fmt.Fprintf(&b, "extensions    %4x %4x\n", m.Extensions.S, m.Extensions.E)

	fmt.Fprintf(&b, "version leg   %04x %04x\n", m.RecordLegacyVersion, m.HelloLegacyVersion)
	fmt.Fprintf(&b, "version       %04x\n", m.Version)

	for _, ext := range m.Exts {
		ext.dump(&b, buf)
	}

	if !m.KeyShare.IsZero() {
		m.KeyShare.dump(&b, buf)
	}

	return b.String()
}
