package rawtls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Hellos are the first records of the captures, see TestCapture.
func TestClientHello(t *testing.T) {
	for _, name := range captures {
		file := name + "_client.bin"

		t.Run(file, func(t *testing.T) {
			data := firstRecord(readTestdata(t, file))

			var c ClientSide
			var m ClientHello

			i, err := c.ParseHello(data, &m)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
			}

			b := c.AppendHello(nil, &m, data)
			if d := diffAt(b, data[:i]); d >= 0 {
				t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
			}

			b = c.AppendHello(append(b[:0], 0xff, 0xff), &m, data) // reused buffer, non empty prefix
			if d := diffAt(b[2:], data[:i]); d >= 0 {
				t.Errorf("append to prefix: differs at %#x, encoded %#x, wanted %#x", d, len(b)-2, i)
			}

			for _, step := range fragmentSteps {
				frag := fragment(RecHandshake, m.RecordLegacyVersion, data[5:], step)

				var f ClientHello

				msg, ver, j, err := c.HandshakeMessage(nil, frag, 0)
				if err != nil || j != len(frag) {
					t.Fatalf("step %d: reassemble: %d/%d %v", step, j, len(frag), err)
				}

				_, err = c.ParseHelloMessage(msg, 0, &f)
				if err != nil {
					t.Errorf("step %d: parse: %v", step, err)
				}

				f.RecordLegacyVersion = ver

				b = c.AppendHello(b[:0], &f, msg)
				if d := diffAt(b, data); d >= 0 {
					t.Errorf("step %d: append: differs at %#x", step, d)
				}
			}

			// t.Logf("hello %+v\n", m)
			if t.Failed() {
				t.Logf("\n%s", m.Dump(data))
				t.Logf("data\n%s", hex.Dump(data))
			}
		})
	}
}

func TestServerHello(t *testing.T) {
	for _, name := range captures {
		file := name + "_server.bin"

		t.Run(file, func(t *testing.T) {
			data := firstRecord(readTestdata(t, file))

			var s ServerSide
			var m ServerHello

			i, err := s.ParseHello(data, &m)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
			}

			b := s.AppendHello(nil, &m, data)
			if d := diffAt(b, data[:i]); d >= 0 {
				t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
			}

			b = s.AppendHello(append(b[:0], 0xff, 0xff), &m, data) // reused buffer, non empty prefix
			if d := diffAt(b[2:], data[:i]); d >= 0 {
				t.Errorf("append to prefix: differs at %#x, encoded %#x, wanted %#x", d, len(b)-2, i)
			}

			for _, step := range fragmentSteps {
				frag := fragment(RecHandshake, m.RecordLegacyVersion, data[5:], step)

				var f ServerHello

				msg, ver, j, err := s.HandshakeMessage(nil, frag, 0)
				if err != nil || j != len(frag) {
					t.Fatalf("step %d: reassemble: %d/%d %v", step, j, len(frag), err)
				}

				_, err = s.ParseHelloMessage(msg, 0, &f)
				if err != nil {
					t.Errorf("step %d: parse: %v", step, err)
				}

				f.RecordLegacyVersion = ver

				b = s.AppendHello(b[:0], &f, msg)
				if d := diffAt(b, data); d >= 0 {
					t.Errorf("step %d: append: differs at %#x", step, d)
				}
			}

			if t.Failed() {
				t.Logf("\n%s", m.Dump(data))
				t.Logf("data\n%s", hex.Dump(data))
			}
		})
	}
}

// fragmentSteps split the header, the random and the extensions, and make a single record.
var fragmentSteps = []int{1, 3, 4, 7, 100, 1000, MaxPlaintext}

// firstRecord returns the first record of the stream.
func firstRecord(b []byte) []byte {
	var d Iterator

	_, _, l, st, err := d.RecordHeader(b, 0)
	if err != nil || st+l > len(b) {
		return b
	}

	return b[:st+l]
}

func diffAt(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}

	if len(a) != len(b) {
		return min(len(a), len(b))
	}

	return -1
}

// ClientHello and ServerHello messages of RFC8448 section 3 rebuilt with the builders:
// extensions we have builders for are made from the parsed values, the rest are copied.
func TestHelloMessagesRFC8448(t *testing.T) {
	var c ClientSide
	var s ServerSide
	var ch ClientHello
	var sh ServerHello

	src := unhex(t, rfcClientHello)

	i, err := c.ParseHelloMessage(src, 0, &ch)
	if err != nil || i != len(src) {
		t.Fatalf("parse client hello: %d/%d %v", i, len(src), err)
	}

	if got := string(ch.ServerName.Data(src)); got != "server" {
		t.Errorf("server name %q", got)
	}
	if len(ch.KeyShare) != 1 || ch.KeyShare[0].Group != GroupX25519 || hex.EncodeToString(ch.KeyShare[0].Data(src)) != rfcClientPub {
		t.Errorf("key share %+v", ch.KeyShare)
	}

	b, hs, ext := c.OpenHello(nil, ch.Random.Data(src), ch.Session.Data(src), list16[CipherSuite](ch.CipherSuites.Data(src))...)

	for _, x := range ch.Exts {
		switch x.Type {
		case ExtServerName:
			b = c.AppendExtServerName(b, string(ch.ServerName.Data(src)))
		case ExtSupportedGroups:
			b = c.AppendExtSupportedGroups(b, list16[KeyGroup](ch.SupportedGroups.Data(src))...)
		case ExtSignatureAlgorithms:
			b = c.AppendExtSignatureAlgorithms(b, list16[SignatureScheme](ch.SignatureAlgorithms.Data(src))...)
		case ExtSupportedVersions:
			b = c.AppendExtSupportedVersions(b, ch.Versions...)
		case ExtKeyShare:
			var st, list int

			b, st = c.OpenExt(b, ExtKeyShare)
			b, list = c.OpenLen16(b)

			for _, k := range ch.KeyShare {
				b = c.AppendKeyShareEntry(b, k.Group, k.Data(src))
			}

			b = c.CloseLen16(b, list)
			b = c.CloseExt(b, st)
		default:
			b = c.AppendExt(b, src, x)
		}
	}

	b = c.CloseHello(b, hs, ext)

	if d := diffAt(b, src); d >= 0 {
		t.Errorf("client hello differs at %#x\n got  %x\n want %x", d, b, src)
	}

	src = unhex(t, rfcServerHello)

	i, err = s.ParseHelloMessage(src, 0, &sh)
	if err != nil || i != len(src) {
		t.Fatalf("parse server hello: %d/%d %v", i, len(src), err)
	}

	if sh.IsHelloRetryRequest(src) || sh.Version != VerTLS13 || sh.KeyShare.Group != GroupX25519 ||
		hex.EncodeToString(sh.KeyShare.Data(src)) != rfcServerPub {
		t.Errorf("server hello: version %x key share %+v", sh.Version, sh.KeyShare)
	}

	b = appendServerHello(t, nil, &sh, src)

	if d := diffAt(b, src); d >= 0 {
		t.Errorf("server hello differs at %#x\n got  %x\n want %x", d, b, src)
	}
}

func TestHelloRetryRequestRFC8448(t *testing.T) {
	var c ClientSide
	var s ServerSide
	var ch ClientHello
	var hrr ServerHello

	src := unhex(t, rfcHRRHelloRetryRequest)

	_, err := s.ParseHelloMessage(src, 0, &hrr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !hrr.IsHelloRetryRequest(src) || hrr.KeyShare.Group != GroupSecp256r1 || hrr.KeyShare.Length != 0 || hrr.Cookie.IsZero() {
		t.Errorf("hello retry request: key share %+v cookie %v", hrr.KeyShare, hrr.Cookie)
	}

	b := appendServerHello(t, nil, &hrr, src)

	if d := diffAt(b, src); d >= 0 {
		t.Errorf("hello retry request differs at %#x\n got  %x\n want %x", d, b, src)
	}

	ch2 := unhex(t, rfcHRRClientHello2)

	_, err = c.ParseHelloMessage(ch2, 0, &ch)
	if err != nil {
		t.Fatalf("parse client hello 2: %v", err)
	}

	if !bytes.Equal(ch.Cookie.Data(ch2), hrr.Cookie.Data(src)) {
		t.Errorf("client hello 2 cookie %x, wanted %x", ch.Cookie.Data(ch2), hrr.Cookie.Data(src))
	}
}

// appendServerHello rebuilds ServerHello or HelloRetryRequest from the parsed message.
func appendServerHello(t *testing.T, b []byte, m *ServerHello, src []byte) []byte {
	var s ServerSide

	b, hs, ext := s.OpenHello(b, m.Random.Data(src), m.Session.Data(src), m.CipherSuite)

	for _, x := range m.Exts {
		var st int

		switch x.Type {
		case ExtSupportedVersions:
			b, st = s.OpenExt(b, ExtSupportedVersions)
			b = appendU16(b, m.Version)
			b = s.CloseExt(b, st)
		case ExtKeyShare:
			b, st = s.OpenExt(b, ExtKeyShare)

			if m.IsHelloRetryRequest(src) {
				b = appendU16(b, m.KeyShare.Group)
			} else {
				b = s.AppendKeyShareEntry(b, m.KeyShare.Group, m.KeyShare.Data(src))
			}

			b = s.CloseExt(b, st)
		case ExtCookie:
			var l int

			b, st = s.OpenExt(b, ExtCookie)
			b, l = s.OpenLen16(b)
			b = append(b, m.Cookie.Data(src)...)
			b = s.CloseLen16(b, l)
			b = s.CloseExt(b, st)
		default:
			t.Errorf("unexpected server hello extension %x", x.Type)
		}
	}

	return s.CloseHello(b, hs, ext)
}

// Ranges are uint16, so a message ending past 0xffff can't be represented.
// The declared length here is 0x10000 over the real message:
// wrapped ranges would parse it as that real message and report a wrong end.
func TestHelloMessageTooLong(t *testing.T) {
	var c ClientSide
	var m ClientHello

	b, hs, ext := c.OpenHello(nil, make([]byte, 32), nil, TLS_AES_128_GCM_SHA256)
	b = c.CloseHello(b, hs, ext)

	c.SetLen24(b, hs, len(b)-hs+0x10000)
	b = appendZeros(b, 0x10000)

	i, err := c.ParseHelloMessage(b, 0, &m)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("wanted %v, got %d %v", ErrMalformed, i, err)
	}
}
