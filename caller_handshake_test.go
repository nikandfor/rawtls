package rawtls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"sync"
	"testing"
)

// TestCallerClientHandshake runs a client handshake with the exported API only against crypto/tls server,
// as a custom client like REALITY's does.
func TestCallerClientHandshake(t *testing.T) {
	var e Emitter
	var cs ClientSide
	var ss ServerSide
	var ks KeyShare
	var sch Schedule
	var sh ServerHello

	cconf, sconf := testConfigs(t, "ed25519")
	cn, sn := tcpPipe(t)

	srv := tls.Server(sn, sconf)
	defer func() { _ = srv.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Go(func() {
		echo(t, srv)
	})

	c := &Conn{Conn: cn}
	defer func() { _ = c.Close() }()

	random := make([]byte, 32)
	session := make([]byte, 32)

	_, _ = rand.Read(random)
	_, _ = rand.Read(session)

	pub, err := ks.Generate(GroupX25519)
	if err != nil {
		t.Fatalf("generate key share: %v", err)
	}

	b, h, ext := cs.OpenHello(nil, random, session, TLS_AES_128_GCM_SHA256)
	b = cs.AppendExtServerName(b, cconf.ServerName)
	b = cs.AppendExtSupportedVersions(b, VerTLS13)
	b = cs.AppendExtSupportedGroups(b, GroupX25519)
	b = cs.AppendExtSignatureAlgorithms(b, SigEd25519)

	b, st := cs.OpenExt(b, ExtKeyShare)
	b, list := cs.OpenLen16(b)
	b = cs.AppendKeyShareEntry(b, GroupX25519, pub)
	b = cs.CloseLen16(b, list)
	b = cs.CloseExt(b, st)

	hello := cs.CloseHello(b, h, ext)

	_, err = cn.Write(c.AppendHandshake(nil, VerTLS10, hello))
	if err != nil {
		t.Fatalf("write client hello: %v", err)
	}

	m := readHandshake(t, c, MsgServerHello)

	_, err = ss.ParseHelloMessage(m, 0, &sh)
	if err != nil {
		t.Fatalf("parse server hello: %v", err)
	}

	suite := sh.CipherSuite

	err = sch.Reset(suite)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}

	sch.Transcript.Write(hello)
	sch.Transcript.Write(m)

	shared, err := ks.SharedSecret(sh.KeyShare.Data(m))
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}

	chs, shs, err := sch.HandshakeSecrets(shared)
	if err != nil {
		t.Fatalf("handshake secrets: %v", err)
	}

	err = c.SetInKeys(suite, shs)
	if err != nil {
		t.Fatalf("set in keys: %v", err)
	}

	m = readHandshake(t, c, MsgEncryptedExtensions)
	sch.Transcript.Write(m)

	m = readHandshake(t, c, MsgCertificate)
	sch.Transcript.Write(m)

	leaf, err := parseLeaf(ss, m)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}

	m = readHandshake(t, c, MsgCertificateVerify)

	scheme, sig, _, err := ss.CertificateVerify(m, 0)
	if err != nil || scheme != SigEd25519 {
		t.Fatalf("certificate verify: %04x %v", scheme, err)
	}

	if !ed25519.Verify(leaf.PublicKey.(ed25519.PublicKey), AppendSignedContent(nil, true, sch.Transcript.Sum(nil)), sig) {
		t.Fatalf("bad certificate verify signature")
	}

	sch.Transcript.Write(m)

	m = readHandshake(t, c, MsgFinished)

	verify, _, err := ss.Finished(m, 0)
	if err != nil {
		t.Fatalf("finished: %v", err)
	}

	err = checkFinished(&sch, shs, verify)
	if err != nil {
		t.Fatalf("server finished: %v", err)
	}

	sch.Transcript.Write(m)

	capp, sapp, err := sch.ApplicationSecrets()
	if err != nil {
		t.Fatalf("application secrets: %v", err)
	}

	err = c.SetInKeys(suite, sapp)
	if err != nil {
		t.Fatalf("set in keys: %v", err)
	}

	verify, err = sch.Finished(chs)
	if err != nil {
		t.Fatalf("client finished: %v", err)
	}

	err = c.SetOutKeys(suite, chs)
	if err != nil {
		t.Fatalf("set out keys: %v", err)
	}

	w := c.AppendChangeCipherSpec(nil)
	w = c.AppendHandshake(w, VerTLS12, e.AppendFinished(nil, verify))

	err = c.SetOutKeys(suite, capp)
	if err != nil {
		t.Fatalf("set out keys: %v", err)
	}

	_, err = cn.Write(w)
	if err != nil {
		t.Fatalf("write client finished: %v", err)
	}

	ping(t, c)
}

// TestCallerServerHandshake runs a server handshake with the exported API only against crypto/tls client,
// as a custom server like REALITY's does.
func TestCallerServerHandshake(t *testing.T) {
	var cs ClientSide
	var ss ServerSide
	var sch Schedule
	var ch ClientHello

	cconf, sconf := testConfigs(t, "ed25519")
	cn, sn := tcpPipe(t)

	cli := tls.Client(cn, cconf)
	defer func() { _ = cli.Close() }()

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Go(func() {
		ping(t, cli)
	})

	c := &Conn{Conn: sn}
	defer func() { _ = c.Close() }()

	m := readHandshake(t, c, MsgClientHello)
	hello := bytes.Clone(m) // valid until the next read

	_, err := cs.ParseHelloMessage(hello, 0, &ch)
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}

	var share []byte

	for _, k := range ch.KeyShare {
		if k.Group == GroupX25519 {
			share = k.Data(hello)
		}
	}

	pub, shared, err := ServerKeyShare(GroupX25519, share)
	if err != nil {
		t.Fatalf("server key share: %v", err)
	}

	suite := TLS_AES_128_GCM_SHA256
	random := make([]byte, 32)

	_, _ = rand.Read(random)

	b, h, ext := ss.OpenHello(nil, random, ch.Session.Data(hello), suite)
	b = ss.AppendExtSelectedVersion(b, VerTLS13)

	b, st := ss.OpenExt(b, ExtKeyShare)
	b = ss.AppendKeyShareEntry(b, GroupX25519, pub)
	b = ss.CloseExt(b, st)

	sh := ss.CloseHello(b, h, ext)

	err = sch.Reset(suite)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}

	sch.Transcript.Write(hello)
	sch.Transcript.Write(sh)

	chs, shs, err := sch.HandshakeSecrets(shared)
	if err != nil {
		t.Fatalf("handshake secrets: %v", err)
	}

	cert := sconf.Certificates[0]

	flight, h, ext := ss.OpenEncryptedExtensions(nil)
	flight = ss.CloseEncryptedExtensions(flight, h, ext)
	flight = ss.AppendCertificate(flight, nil, cert.Certificate...)

	sch.Transcript.Write(flight)
	st = len(flight)

	sig := ed25519.Sign(cert.PrivateKey.(ed25519.PrivateKey), AppendSignedContent(nil, true, sch.Transcript.Sum(nil)))
	flight = ss.AppendCertificateVerify(flight, SigEd25519, sig)

	sch.Transcript.Write(flight[st:])
	st = len(flight)

	verify, err := sch.Finished(shs)
	if err != nil {
		t.Fatalf("server finished: %v", err)
	}

	flight = ss.AppendFinished(flight, verify)

	sch.Transcript.Write(flight[st:])

	capp, sapp, err := sch.ApplicationSecrets()
	if err != nil {
		t.Fatalf("application secrets: %v", err)
	}

	w := c.AppendHandshake(nil, VerTLS12, sh)
	w = c.AppendChangeCipherSpec(w)

	err = c.SetOutKeys(suite, shs)
	if err != nil {
		t.Fatalf("set out keys: %v", err)
	}

	w = c.AppendHandshake(w, VerTLS12, flight)

	err = c.SetOutKeys(suite, sapp)
	if err != nil {
		t.Fatalf("set out keys: %v", err)
	}

	_, err = sn.Write(w)
	if err != nil {
		t.Fatalf("write server flight: %v", err)
	}

	err = c.SetInKeys(suite, chs)
	if err != nil {
		t.Fatalf("set in keys: %v", err)
	}

	m = readHandshake(t, c, MsgFinished) // ChangeCipherSpec is dropped

	verify, _, err = ss.Finished(m, 0)
	if err != nil {
		t.Fatalf("finished: %v", err)
	}

	err = checkFinished(&sch, chs, verify)
	if err != nil {
		t.Fatalf("client finished: %v", err)
	}

	err = c.SetInKeys(suite, capp)
	if err != nil {
		t.Fatalf("set in keys: %v", err)
	}

	echo(t, c)
}

func readHandshake(t *testing.T, c *Conn, want HandshakeType) []byte {
	t.Helper()

	msg, m, err := c.ReadHandshake()
	if err != nil || msg != want {
		t.Fatalf("read handshake: %x %v, wanted %x", msg, err, want)
	}

	return m
}

// ping writes ping and expects pong.
func ping(t *testing.T, c io.ReadWriter) {
	t.Helper()

	_, err := c.Write([]byte("ping"))
	if err != nil {
		t.Errorf("write ping: %v", err)
		return
	}

	var buf [4]byte

	_, err = io.ReadFull(c, buf[:])
	if err != nil || string(buf[:]) != "pong" {
		t.Errorf("read pong: %q %v", buf, err)
	}
}

// echo expects ping and writes pong.
func echo(t *testing.T, c io.ReadWriter) {
	t.Helper()

	var buf [4]byte

	_, err := io.ReadFull(c, buf[:])
	if err != nil || string(buf[:]) != "ping" {
		t.Errorf("read ping: %q %v", buf, err)
		return
	}

	_, err = c.Write([]byte("pong"))
	if err != nil {
		t.Errorf("write pong: %v", err)
	}
}
