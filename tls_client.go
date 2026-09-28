package rawtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"
)

type (
	clientHandshake struct {
		c   *Conn
		cfg *tls.Config

		serverName string
		groups     []KeyGroup

		shares []KeyShare
		pubs   [][]byte

		random  [32]byte
		session [32]byte
		hello   []byte // ClientHello until it's written into the transcript
		cookie  []byte

		s       Schedule
		retried bool
		sentCCS bool

		clientSecret []byte
		serverSecret []byte

		certRequested bool
		certContext   []byte

		certs  []*x509.Certificate
		chains [][]*x509.Certificate
	}
)

var clientSuites = []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}

// Client returns TLS 1.3 client connection over conn, like crypto/tls.Client.
// The handshake runs on the first Read or Write, or by Handshake.
//
// Session resumption, 0-RTT and client certificates are not supported,
// an empty Certificate is sent if the server asks for one.
// Config fields used: ServerName, InsecureSkipVerify, RootCAs, Time, NextProtos,
// CurvePreferences, VerifyPeerCertificate and VerifyConnection.
func Client(conn net.Conn, config *tls.Config) *Conn {
	return &Conn{Conn: conn, config: config, isClient: true}
}

func (c *Conn) clientHandshake() (err error) {
	hs := clientHandshake{c: c, cfg: c.config}

	return hs.run()
}

func (hs *clientHandshake) run() (err error) {
	var sh ServerHello

	c := hs.c

	hs.serverName = hs.cfg.ServerName
	if hs.serverName == "" && !hs.cfg.InsecureSkipVerify {
		return errors.New("either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	hs.groups = configGroups(hs.cfg)
	if len(hs.groups) == 0 {
		return fmt.Errorf("%w: no supported curve preferences", ErrUnsupported)
	}

	_, _ = rand.Read(hs.random[:]) // never fails
	_, _ = rand.Read(hs.session[:])

	err = hs.addShare(hs.groups[0])
	if err != nil {
		return err
	}

	if hs.groups[0] == GroupX25519MLKEM768 && slices.Contains(hs.groups, GroupX25519) {
		err = hs.addShare(GroupX25519)
		if err != nil {
			return err
		}
	}

	err = hs.sendHello(VerTLS10)
	if err != nil {
		return err
	}

	m, err := hs.readServerHello(&sh)
	if err != nil {
		return err
	}

	if sh.IsHelloRetryRequest(m) {
		err = hs.retry(&sh, m)
		if err != nil {
			return err
		}

		m, err = hs.readServerHello(&sh)
		if err != nil {
			return err
		}

		if sh.IsHelloRetryRequest(m) || sh.CipherSuite != hs.s.Suite {
			return c.fail(fmt.Errorf("%w: server hello after retry", AlertIllegalParameter))
		}
	} else {
		err = hs.s.Reset(sh.CipherSuite)
		if err != nil {
			return c.fail(err)
		}

		hs.s.Transcript.Write(hs.hello)
	}

	hs.s.Transcript.Write(m)

	shared, err := hs.sharedSecret(&sh, m)
	if err != nil {
		return c.fail(err)
	}

	hs.clientSecret, hs.serverSecret, err = hs.s.HandshakeSecrets(shared)
	if err != nil {
		return c.fail(err)
	}

	err = c.SetInKeys(hs.s.Suite, hs.serverSecret)
	if err != nil {
		return err
	}

	err = c.SetOutKeys(hs.s.Suite, hs.clientSecret) // even alerts are protected from now on
	if err != nil {
		return c.fail(err)
	}

	err = hs.readEncryptedExtensions()
	if err != nil {
		return err
	}

	err = hs.readCertificate()
	if err != nil {
		return err
	}

	err = hs.readCertificateVerify()
	if err != nil {
		return err
	}

	err = hs.readFinished()
	if err != nil {
		return err
	}

	clientApp, serverApp, err := hs.s.ApplicationSecrets()
	if err != nil {
		return c.fail(err)
	}

	err = c.SetInKeys(hs.s.Suite, serverApp)
	if err != nil {
		return err
	}

	err = hs.sendFinished(clientApp)
	if err != nil {
		return err
	}

	c.ServerName = hs.serverName
	c.peerCertificates = hs.certs
	c.verifiedChains = hs.chains

	return nil
}

func (hs *clientHandshake) addShare(g KeyGroup) error {
	var k KeyShare

	pub, err := k.Generate(g)
	if err != nil {
		return err
	}

	hs.shares = append(hs.shares, k)
	hs.pubs = append(hs.pubs, pub)

	return nil
}

func (hs *clientHandshake) sendHello(ver ProtocolVersion) error {
	var cs ClientSide

	c := hs.c

	b, h, ext := cs.OpenHello(hs.hello[:0], hs.random[:], hs.session[:], clientSuites...)

	if hs.serverName != "" && net.ParseIP(hs.serverName) == nil {
		b = cs.AppendExtServerName(b, hs.serverName)
	}

	b = cs.AppendExtSupportedVersions(b, VerTLS13)
	b = cs.AppendExtSupportedGroups(b, hs.groups...)
	b = cs.AppendExtSignatureAlgorithms(b, defaultSignatureSchemes...)

	var st, list int

	b, st = cs.OpenExt(b, ExtKeyShare)
	b, list = cs.OpenLen16(b)

	for i, k := range hs.shares {
		b = cs.AppendKeyShareEntry(b, k.Group, hs.pubs[i])
	}

	b = cs.CloseLen16(b, list)
	b = cs.CloseExt(b, st)

	if len(hs.cfg.NextProtos) != 0 {
		b = cs.AppendExtALPN(b, hs.cfg.NextProtos...)
	}

	if hs.cookie != nil {
		b, st = cs.OpenExt(b, ExtCookie)
		b, list = cs.OpenLen16(b)
		b = append(b, hs.cookie...)
		b = cs.CloseLen16(b, list)
		b = cs.CloseExt(b, st)
	}

	b = cs.CloseHello(b, h, ext)

	hs.hello = b

	defer c.wmu.Unlock()
	c.wmu.Lock()

	w := c.buf()

	if hs.retried && !hs.sentCCS {
		w = c.AppendChangeCipherSpec(w)
		hs.sentCCS = true
	}

	w = c.AppendHandshake(w, ver, b)

	return c.write(w)
}

// readServerHello reads ServerHello or HelloRetryRequest and checks the fields common for both.
func (hs *clientHandshake) readServerHello(sh *ServerHello) ([]byte, error) {
	var ss ServerSide

	c := hs.c

	msg, m, err := c.readMessage()
	if err != nil {
		return nil, err
	}
	if msg != MsgServerHello {
		return nil, c.fail(fmt.Errorf("%w: wanted server hello, got %x", AlertUnexpectedMessage, msg))
	}

	_, err = ss.ParseHelloMessage(m, 0, sh)
	if err != nil {
		return nil, c.fail(fmt.Errorf("%w: server hello: %w", AlertDecodeError, err))
	}

	switch {
	case sh.Version != VerTLS13:
		return nil, c.fail(fmt.Errorf("%w: server version %04x", AlertProtocolVersion, sh.Version))
	case !bytes.Equal(sh.Session.Data(m), hs.session[:]):
		return nil, c.fail(fmt.Errorf("%w: session id is not echoed", AlertIllegalParameter))
	case !slices.Contains(clientSuites, sh.CipherSuite):
		return nil, c.fail(fmt.Errorf("%w: cipher suite %04x is not offered", AlertIllegalParameter, sh.CipherSuite))
	case sh.Compression != 0:
		return nil, c.fail(fmt.Errorf("%w: compression %x", AlertIllegalParameter, sh.Compression))
	}

	return m, nil
}

// retry handles HelloRetryRequest and sends the second ClientHello.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
func (hs *clientHandshake) retry(hrr *ServerHello, m []byte) error {
	c := hs.c
	g := hrr.KeyShare.Group

	if !slices.Contains(hs.groups, g) || slices.ContainsFunc(hs.shares, func(k KeyShare) bool { return k.Group == g }) {
		return c.fail(fmt.Errorf("%w: retry group %04x", AlertIllegalParameter, g))
	}

	err := hs.s.Reset(hrr.CipherSuite)
	if err != nil {
		return c.fail(err)
	}

	hs.s.Transcript.Write(hs.hello)
	hs.s.HelloRetryRequest()
	hs.s.Transcript.Write(m)

	if !hrr.Cookie.IsZero() {
		hs.cookie = bytes.Clone(hrr.Cookie.Data(m))
	}

	hs.retried = true

	hs.shares = hs.shares[:0]
	hs.pubs = hs.pubs[:0]

	err = hs.addShare(g)
	if err != nil {
		return err
	}

	err = hs.sendHello(VerTLS12)
	if err != nil {
		return err
	}

	hs.s.Transcript.Write(hs.hello)

	return nil
}

func (hs *clientHandshake) sharedSecret(sh *ServerHello, m []byte) ([]byte, error) {
	for i := range hs.shares {
		if hs.shares[i].Group == sh.KeyShare.Group && sh.KeyShare.Length != 0 {
			return hs.shares[i].SharedSecret(sh.KeyShare.Data(m))
		}
	}

	return nil, fmt.Errorf("%w: server key share group %04x", AlertIllegalParameter, sh.KeyShare.Group)
}

func (hs *clientHandshake) readEncryptedExtensions() error {
	var ss ServerSide
	var ee EncryptedExtensions

	c := hs.c

	msg, m, err := c.readMessage()
	if err != nil {
		return err
	}
	if msg != MsgEncryptedExtensions {
		return c.fail(fmt.Errorf("%w: wanted encrypted extensions, got %x", AlertUnexpectedMessage, msg))
	}

	_, err = ss.ParseEncryptedExtensions(m, 0, &ee)
	if err != nil {
		return c.fail(fmt.Errorf("%w: encrypted extensions: %w", AlertDecodeError, err))
	}

	if !ee.ALPN.IsZero() {
		p := string(ee.ALPN.Data(m))

		if !slices.Contains(hs.cfg.NextProtos, p) {
			return c.fail(fmt.Errorf("%w: server selected unadvertised protocol %q", AlertUnsupportedExtension, p))
		}

		c.NegotiatedProtocol = p
	}

	hs.s.Transcript.Write(m)

	return nil
}

func (hs *clientHandshake) readCertificate() error {
	var d Iterator

	c := hs.c

	msg, m, err := c.readMessage()
	if err != nil {
		return err
	}

	if msg == MsgCertificateRequest {
		hs.certRequested = true

		body, _, err := d.Message(m, 0, MsgCertificateRequest)
		if err != nil || len(body) == 0 || 1+int(body[0]) > len(body) {
			return c.fail(fmt.Errorf("%w: certificate request", AlertDecodeError))
		}

		l := int(body[0])

		hs.certContext = bytes.Clone(body[1 : 1+l])
		hs.s.Transcript.Write(m)

		msg, m, err = c.readMessage()
		if err != nil {
			return err
		}
	}

	if msg != MsgCertificate {
		return c.fail(fmt.Errorf("%w: wanted certificate, got %x", AlertUnexpectedMessage, msg))
	}

	context, list, _, err := d.Certificate(m, 0)
	if err != nil {
		return c.fail(fmt.Errorf("%w: certificate: %w", AlertDecodeError, err))
	}
	if len(context) != 0 {
		return c.fail(fmt.Errorf("%w: certificate request context", AlertIllegalParameter))
	}

	for i := 0; i < len(list); {
		var raw []byte

		raw, i, err = d.CertificateEntry(list, i)
		if err != nil {
			return c.fail(fmt.Errorf("%w: certificate entry: %w", AlertDecodeError, err))
		}

		cert, err := x509.ParseCertificate(bytes.Clone(raw))
		if err != nil {
			return c.fail(fmt.Errorf("%w: parse certificate: %w", AlertBadCertificate, err))
		}

		hs.certs = append(hs.certs, cert)
	}

	if len(hs.certs) == 0 {
		return c.fail(fmt.Errorf("%w: no server certificate", AlertDecodeError))
	}

	hs.s.Transcript.Write(m)

	return hs.verifyCertificates()
}

func (hs *clientHandshake) verifyCertificates() (err error) {
	c := hs.c
	cfg := hs.cfg

	if !cfg.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         cfg.RootCAs,
			Intermediates: x509.NewCertPool(),
			DNSName:       hs.serverName,
			CurrentTime:   now(cfg),
		}

		for _, cert := range hs.certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		hs.chains, err = hs.certs[0].Verify(opts)
		if err != nil {
			return c.fail(fmt.Errorf("verify certificate: %w: %w", certificateAlert(err), err))
		}
	}

	if cfg.VerifyPeerCertificate != nil {
		raw := make([][]byte, len(hs.certs))

		for i, cert := range hs.certs {
			raw[i] = cert.Raw
		}

		err = cfg.VerifyPeerCertificate(raw, hs.chains)
		if err != nil {
			return c.fail(fmt.Errorf("verify peer certificate: %w: %w", AlertBadCertificate, err))
		}
	}

	return nil
}

func (hs *clientHandshake) readCertificateVerify() error {
	var d Iterator

	c := hs.c
	sum := hs.s.Transcript.Sum(nil)

	msg, m, err := c.readMessage()
	if err != nil {
		return err
	}
	if msg != MsgCertificateVerify {
		return c.fail(fmt.Errorf("%w: wanted certificate verify, got %x", AlertUnexpectedMessage, msg))
	}

	scheme, sig, _, err := d.CertificateVerify(m, 0)
	if err != nil {
		return c.fail(fmt.Errorf("%w: certificate verify: %w", AlertDecodeError, err))
	}

	err = verifySignature(hs.certs[0].PublicKey, scheme, AppendSignedContent(nil, true, sum), sig)
	if err != nil {
		return c.fail(err)
	}

	hs.s.Transcript.Write(m)

	if hs.cfg.VerifyConnection != nil {
		c.ServerName = hs.serverName
		c.peerCertificates = hs.certs
		c.verifiedChains = hs.chains

		err = hs.cfg.VerifyConnection(c.state(hs.s.Suite))
		if err != nil {
			return c.fail(fmt.Errorf("verify connection: %w: %w", AlertBadCertificate, err))
		}
	}

	return nil
}

func (hs *clientHandshake) readFinished() error {
	var d Iterator

	c := hs.c

	want, err := hs.s.Finished(hs.serverSecret)
	if err != nil {
		return c.fail(err)
	}

	msg, m, err := c.readMessage()
	if err != nil {
		return err
	}
	if msg != MsgFinished {
		return c.fail(fmt.Errorf("%w: wanted finished, got %x", AlertUnexpectedMessage, msg))
	}

	verify, _, err := d.Finished(m, 0)
	if err != nil {
		return c.fail(fmt.Errorf("%w: finished: %w", AlertDecodeError, err))
	}

	if !hmac.Equal(verify, want) {
		return c.fail(fmt.Errorf("%w: bad server finished", AlertDecryptError))
	}

	hs.s.Transcript.Write(m)

	return nil
}

// sendFinished sends the client flight and switches Out to the application secret.
func (hs *clientHandshake) sendFinished(clientApp []byte) error {
	var e Emitter
	var msgs []byte

	c := hs.c

	if hs.certRequested {
		msgs = e.AppendCertificate(msgs, hs.certContext)
		hs.s.Transcript.Write(msgs)
	}

	fin, err := hs.s.Finished(hs.clientSecret)
	if err != nil {
		return c.fail(err)
	}

	msgs = e.AppendFinished(msgs, fin)

	defer c.wmu.Unlock()
	c.wmu.Lock()

	b := c.buf()

	if !hs.sentCCS {
		b = c.AppendChangeCipherSpec(b)
	}

	b = c.AppendHandshake(b, VerTLS12, msgs)

	err = c.Out.ResetSecret(hs.s.Suite, clientApp)
	if err != nil {
		return err
	}

	return c.write(b)
}

// configGroups returns the groups of CurvePreferences we support, or default ones.
func configGroups(cfg *tls.Config) []KeyGroup {
	if len(cfg.CurvePreferences) == 0 {
		return defaultGroups
	}

	var gs []KeyGroup

	for _, id := range cfg.CurvePreferences {
		if g := KeyGroup(id); slices.Contains(defaultGroups, g) {
			gs = append(gs, g)
		}
	}

	return gs
}

func certificateAlert(err error) AlertDescription {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError

	switch {
	case errors.As(err, &unknown):
		return AlertUnknownCA
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return AlertCertificateExpired
	}

	return AlertBadCertificate
}

func now(cfg *tls.Config) time.Time {
	if cfg.Time != nil {
		return cfg.Time()
	}

	return time.Now()
}
