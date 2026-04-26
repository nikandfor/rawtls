package rawtls

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"runtime"
	"strings"
)

type (
	ClientHello struct {
		Record    BytesRange
		Handshake BytesRange

		Random       BytesRange
		Session      BytesRange
		CipherSuites BytesRange
		Compression  BytesRange
		Extensions   BytesRange

		RecordLegacyVerson ProtocolVersion
		HelloLegacyVerson  ProtocolVersion

		ServerName BytesRange

		Exts     []Ext
		Versions []ProtocolVersion
		KeyShare []Key

		extsbuf [4]Ext
		keysbuf [4]Key
		versbuf [4]ProtocolVersion
	}

	ExtensionType   uint16
	ProtocolVersion uint16

	CipherSuite [2]uint8

	Ext struct {
		Type   ExtensionType
		Length uint16
		Offset uint16
	}

	KeyGroup uint16

	Key struct {
		Group  KeyGroup
		Length uint16
		Offset uint16
	}

	BytesRange struct {
		S, E uint16 // start, end
	}

	ints interface {
		~int | ~uint8 | ~uint16 | ~uint32
	}
)

var (
	ErrFragmented  = errors.New("fragmented message")
	ErrShortBuffer = io.ErrShortBuffer
	ErrUnexpected  = errors.New("unexpected message")
	ErrMalformed   = errors.New("malformed message")
)

var zeroRange BytesRange

// Parse parses TLS ClientHello message.
//
// Based on:
//
//	RFC8446: The Transport Layer Security (TLS) Protocol Version 1.3
//	https://datatracker.ietf.org/doc/html/rfc8446#autoid-21
func (m *ClientHello) Parse(b []byte) (i int, err error) {
	// defer func() {
	// 	fmt.Printf("parse client hello  %x, %v  from %v\n", i, err, caller(1))
	// }()

	m.Record, m.Handshake, i, err = parseHandshakeHeader(b, 0, 0x01, &m.RecordLegacyVerson)
	if err != nil {
		return i, err
	}

	// client hello

	if i+40 > m.Handshake.End() {
		return i, ErrMalformed
	}

	m.HelloLegacyVerson = u16[ProtocolVersion](b, &i)

	m.Random = br(i, i+32)
	i += 32

	l := u8[int](b, &i) // session
	if i+l > m.Record.End() {
		return i, ErrMalformed
	}

	m.Session = br(i, i+l)
	i += l

	l = u16[int](b, &i) // cipher suites
	if i+l > m.Record.End() {
		return i, ErrMalformed
	}

	m.CipherSuites = br(i, i+l)
	i += l

	l = u8[int](b, &i) // legacy compression algs
	if i+l > m.Record.End() {
		return i, ErrMalformed
	}

	m.Compression = br(i, i+l)
	i += l

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

func (m *ClientHello) parseExt(b []byte, e Ext) error {
	i := e.Start()

	switch e.Type {
	case 0x0000: // server name
		l := u16[int](b, &i)
		if i+l != e.End() || l < 1 {
			return ErrMalformed
		}

		for end := i + l; i < end; {
			tp := u8[uint8](b, &i)
			l := u16[int](b, &i)
			if i+l > end {
				return ErrMalformed
			}

			if tp == 0x00 { // hostname
				m.ServerName = br(i, i+l)
			}

			i += l
		}
	case 0x002b: // supported versions
		l := u8[int](b, &i)
		if i+l != e.End() || l&1 == 1 {
			return ErrMalformed
		}

		for end := i + l; i < end; {
			ver := u16[ProtocolVersion](b, &i)

			m.Versions = append(m.Versions, ver)
		}
	case 0x0033: // Key Share
		l := u16[int](b, &i)
		if i+l != e.End() {
			return ErrMalformed
		}

		for end := i + l; i < end; {
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

func parseHandshakeHeader(b []byte, st int, msg byte, ver *ProtocolVersion) (rec, hs BytesRange, i int, err error) {
	rec, i, err = parseRecordHeader(b, st, ver)
	if err != nil {
		return rec, hs, i, err
	}

	// handshake start

	if i+4 > rec.End() {
		return rec, hs, rec.Start(), ErrMalformed
	}

	if u8[uint8](b, &i) != msg { // handshake type != message type (client/server hello)
		return rec, hs, i, ErrUnexpected
	}

	l := u24[int](b, &i) // handshake length
	if i+l > rec.End() {
		return rec, hs, i, ErrFragmented
	}

	hs = br(i, i+l)

	if hs.E != rec.E {
		return rec, hs, i, ErrMalformed
	}

	return rec, hs, i, nil
}

func parseRecordHeader(b []byte, st int, ver *ProtocolVersion) (rec BytesRange, i int, err error) {
	i = st

	if i+9 > len(b) {
		err = ErrShortBuffer
		return
	}

	if u8[byte](b, &i) != 0x16 { // record type != tls handshake
		err = ErrUnexpected
		return
	}

	if ver != nil {
		*ver = u16[ProtocolVersion](b, &i)
	} else {
		i += 2
	}

	l := u16[int](b, &i) // record length
	rec = br(i, i+l)

	if i+l > len(b) {
		err = ErrShortBuffer
	}

	return rec, i, err
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
			cip[i] = CipherSuite{data[2*i], data[2*i+1]}
		}
	}

	fmt.Fprintf(&b, "client hello  %4x %4x\n", m.Record.S, m.Record.E)
	fmt.Fprintf(&b, "handshake     %4x %4x\n", m.Handshake.S, m.Handshake.E)
	fmt.Fprintf(&b, "random        %4x %4x\n", m.Random.S, m.Random.E)
	fmt.Fprintf(&b, "session       %4x %4x    %08x\n", m.Session.S, m.Session.E, sess)
	fmt.Fprintf(&b, "cipher        %4x %4x    %04x\n", m.CipherSuites.S, m.CipherSuites.E, cip)
	fmt.Fprintf(&b, "compress      %4x %4x\n", m.Compression.S, m.Compression.E)
	fmt.Fprintf(&b, "extensions    %4x %4x\n", m.Extensions.S, m.Extensions.E)

	fmt.Fprintf(&b, "version leg   %04x %04x\n", m.RecordLegacyVerson, m.HelloLegacyVerson)

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

func u8[T ints](b []byte, i *int) T {
	r := T(b[*i])
	*i++
	return r
}

func u16[T ints](b []byte, i *int) T {
	r := T(b[*i])<<8 + T(b[*i+1])
	*i += 2
	return r
}

func u24[T ints](b []byte, i *int) T {
	r := T(b[*i])<<16 + T(b[*i+1])<<8 + T(b[*i+2])
	*i += 3
	return r
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
func (e Ext) End() int             { return int(e.Offset + e.Length) }
func (e Ext) IsZero() bool         { return e == Ext{} }
func (e Ext) Data(b []byte) []byte { return b[e.Offset : e.Offset+e.Length] }
func (k Key) Start() int           { return int(k.Offset) }
func (k Key) End() int             { return int(k.Offset + k.Length) }
func (k Key) IsZero() bool         { return k == Key{} }
func (k Key) Data(b []byte) []byte { return b[k.Offset : k.Offset+k.Length] }

func caller(d int) string {
	_, file, line, _ := runtime.Caller(1 + d)

	return fmt.Sprintf("%v:%v", filepath.Base(file), line)
}
