package rawtls

import (
	"crypto/x509"
	"errors"
	"testing"
)

// Server messages of RFC8448 section 3, parsed and rebuilt.
func TestHandshakeMessagesRFC8448(t *testing.T) {
	var s ServerSide
	var ee EncryptedExtensions

	src := unhex(t, rfcEncryptedExtensions)

	i, err := s.ParseEncryptedExtensions(src, 0, &ee)
	if err != nil || i != len(src) || !ee.ALPN.IsZero() {
		t.Errorf("parse encrypted extensions: %d/%d %v alpn %v", i, len(src), err, ee.ALPN)
	}

	b, hs, ext := s.OpenEncryptedExtensions(nil)

	for _, x := range ee.Exts {
		b = s.AppendExt(b, src, x)
	}

	b = s.CloseEncryptedExtensions(b, hs, ext)

	checkMessage(t, "encrypted extensions", b, src)

	src = unhex(t, rfcCertificate)

	context, list, i, err := s.Certificate(src, 0)
	if err != nil || i != len(src) || len(context) != 0 {
		t.Fatalf("parse certificate: %d/%d %v context %x", i, len(src), err, context)
	}

	cert, i, err := s.CertificateEntry(list, 0)
	if err != nil || i != len(list) {
		t.Fatalf("parse certificate entry: %d/%d %v", i, len(list), err)
	}

	_, err = x509.ParseCertificate(cert)
	if err != nil {
		t.Errorf("parse x509: %v", err)
	}

	checkMessage(t, "certificate", s.AppendCertificate(nil, context, cert), src)

	src = unhex(t, rfcCertificateVerify)

	scheme, sig, i, err := s.CertificateVerify(src, 0)
	if err != nil || i != len(src) || scheme != SigRSAPSSRSAeSHA256 {
		t.Fatalf("parse certificate verify: %d/%d %v scheme %x", i, len(src), err, scheme)
	}

	checkMessage(t, "certificate verify", s.AppendCertificateVerify(nil, scheme, sig), src)

	src = unhex(t, rfcServerFinished)

	verify, i, err := s.Finished(src, 0)
	if err != nil || i != len(src) || string(verify) != string(unhex(t, rfcServerFinishedVerify)) {
		t.Fatalf("parse finished: %d/%d %v verify %x", i, len(src), err, verify)
	}

	checkMessage(t, "finished", s.AppendFinished(nil, verify), src)
}

func TestALPN(t *testing.T) {
	var c ClientSide
	var s ServerSide
	var ch ClientHello
	var ee EncryptedExtensions

	b, hs, ext := c.OpenHello(nil, make([]byte, 32), nil, TLS_AES_128_GCM_SHA256)
	b = c.AppendExtALPN(b, "h2", "http/1.1")
	b = c.CloseHello(b, hs, ext)

	_, err := c.ParseHelloMessage(b, 0, &ch)
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}

	if got := string(ch.ALPN.Data(b)); got != "\x02h2\x08http/1.1" {
		t.Errorf("client hello alpn %q", got)
	}

	b, hs, ext = s.OpenEncryptedExtensions(nil)
	b = s.AppendExtALPN(b, "h2")
	b = s.CloseEncryptedExtensions(b, hs, ext)

	_, err = s.ParseEncryptedExtensions(b, 0, &ee)
	if err != nil || string(ee.ALPN.Data(b)) != "h2" {
		t.Errorf("encrypted extensions alpn %q %v", ee.ALPN.Data(b), err)
	}

	b, hs, ext = s.OpenEncryptedExtensions(nil)
	b = s.AppendExtALPN(b, "h2", "http/1.1")
	b = s.CloseEncryptedExtensions(b, hs, ext)

	_, err = s.ParseEncryptedExtensions(b, 0, &ee)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("two selected protocols: wanted %v, got %v", ErrMalformed, err)
	}
}

func TestHandshakeMessagesMalformed(t *testing.T) {
	var d Iterator

	for _, tc := range []struct {
		name  string
		msg   []byte
		parse func(b []byte) error
		err   error
	}{{
		name:  "unexpected type",
		msg:   []byte{byte(MsgCertificate), 0, 0, 0},
		parse: func(b []byte) error { _, _, err := d.Finished(b, 0); return err },
		err:   ErrUnexpected,
	}, {
		name:  "incomplete",
		msg:   []byte{byte(MsgFinished), 0, 0, 4, 1, 2},
		parse: func(b []byte) error { _, _, err := d.Finished(b, 0); return err },
		err:   ErrShortBuffer,
	}, {
		name:  "certificate list length",
		msg:   []byte{byte(MsgCertificate), 0, 0, 4, 0, 0, 0, 1},
		parse: func(b []byte) error { _, _, _, err := d.Certificate(b, 0); return err },
		err:   ErrMalformed,
	}, {
		name: "empty certificate entry",
		msg:  []byte{0, 0, 0, 0, 0},
		parse: func(b []byte) error {
			_, _, err := d.CertificateEntry(b, 0)
			return err
		},
		err: ErrMalformed,
	}, {
		name:  "certificate verify signature length",
		msg:   []byte{byte(MsgCertificateVerify), 0, 0, 5, 8, 4, 0, 2, 1},
		parse: func(b []byte) error { _, _, _, err := d.CertificateVerify(b, 0); return err },
		err:   ErrMalformed,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.parse(tc.msg)
			if !errors.Is(err, tc.err) {
				t.Errorf("wanted %v, got %v", tc.err, err)
			}
		})
	}
}

func checkMessage(t *testing.T, name string, got, want []byte) {
	t.Helper()

	if d := diffAt(got, want); d >= 0 {
		t.Errorf("%v differs at %#x\n got  %x\n want %x", name, d, got, want)
	}
}
