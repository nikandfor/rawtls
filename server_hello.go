package rawtls

import (
	"fmt"
	"hash/crc32"
	"strings"
)

type (
	ServerSide struct {
		Emitter
		Iterator
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
		KeyShare Key // Length is 0 in HelloRetryRequest, only the group is selected
		Cookie   BytesRange

		extsbuf [4]Ext
	}
)

// ParseHello parses TLS ServerHello record.
// The record must contain exactly one complete message.
//
// Based on:
//
//	RFC8446: The Transport Layer Security (TLS) Protocol Version 1.3
//	https://datatracker.ietf.org/doc/html/rfc8446#autoid-22
func (s ServerSide) ParseHello(b []byte, m *ServerHello) (i int, err error) {
	// defer func() {
	// 	fmt.Printf("parse server hello  %x, %v  from %v\n", i, err, caller(1))
	// }()

	m.Record, i, err = parseHandshakeRecord(b, 0, &m.RecordLegacyVersion)
	if err != nil {
		return i, err
	}

	i, err = s.ParseHelloMessage(b[:m.Record.End()], i, m)

	return helloRecordEnd(m.Record, i, err)
}

// ParseHelloMessage parses ServerHello handshake message at st.
// HelloRetryRequest is a ServerHello too, see IsHelloRetryRequest.
// Record is left as is.
func (s ServerSide) ParseHelloMessage(b []byte, st int, m *ServerHello) (i int, err error) {
	m.Handshake, i, err = parseMessage(b, st, MsgServerHello)
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

	// the check reserves cipher suite, compression and extensions length too,
	// they are read before they are checked

	l := u8[int](b, &i) // session
	if i+l+5 > end {
		return i, ErrMalformed
	}

	m.Session = br(i, i+l)
	i += l

	m.CipherSuiteOffset = uint16(i)
	m.CipherSuite = u16[CipherSuite](b, &i)

	m.Compression = u8[byte](b, &i)

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

// OpenHello starts ServerHello message: the header and the fields before extensions.
// HelloRetryRequest is started with HelloRetryRequestRandom.
// Extensions are appended then, and the message is finished with CloseHello.
func (s ServerSide) OpenHello(b, random, session []byte, suite CipherSuite) (_ []byte, hs, ext int) {
	if len(random) != 32 {
		panic(len(random))
	}

	b, hs = s.OpenHandshake(b, MsgServerHello)

	b = appendU16(b, VerTLS12)
	b = append(b, random...)

	b, st := s.OpenLen8(b)
	b = append(b, session...)
	b = s.CloseLen8(b, st)

	b = appendU16(b, suite)
	b = appendU8(b, 0) // null compression

	b, ext = s.OpenLen16(b)

	return b, hs, ext
}

func (s ServerSide) CloseHello(b []byte, hs, ext int) []byte {
	b = s.CloseLen16(b, ext)

	return s.CloseHandshake(b, hs)
}

// AppendExtSelectedVersion appends supported_versions extension of ServerHello.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
func (s ServerSide) AppendExtSelectedVersion(b []byte, ver ProtocolVersion) []byte {
	b, st := s.OpenExt(b, ExtSupportedVersions)
	b = appendU16(b, ver)

	return s.CloseExt(b, st)
}

// AppendHello appends TLS ServerHello message m to the buffer b.
// Variable length values are copied from src, the buffer m was parsed from.
func (s ServerSide) AppendHello(b []byte, m *ServerHello, src []byte) []byte {
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
		if e.Length == 2 { // HelloRetryRequest
			m.KeyShare = Key{Group: u16[KeyGroup](b, &i), Offset: uint16(i)}

			return nil
		}

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
	case ExtCookie:
		r, err := parseCookie(b, e)
		if err != nil {
			return err
		}

		m.Cookie = r
	}

	return nil
}

// IsHelloRetryRequest reports whether the parsed ServerHello is a HelloRetryRequest.
func (m *ServerHello) IsHelloRetryRequest(b []byte) bool {
	return string(m.Random.Data(b)) == string(HelloRetryRequestRandom[:])
}

func (m *ServerHello) softResetExts() {
	if m.Exts == nil {
		m.Exts = m.extsbuf[:0]
	} else {
		m.Exts = m.Exts[:0]
	}

	m.Version = 0
	m.KeyShare = Key{}
	m.Cookie = zeroRange
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
