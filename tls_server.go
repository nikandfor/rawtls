package rawtls

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
)

type (
	serverHandshake struct {
		c   *Conn
		cfg *tls.Config

		ch ClientHello

		suite      CipherSuite
		group      KeyGroup
		serverName string
		alpn       string

		cert   *tls.Certificate
		signer crypto.Signer
		scheme SignatureScheme

		s       Schedule
		sentCCS bool

		clientSecret []byte
		serverSecret []byte
	}
)

var serverSuites = []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}

// Server returns TLS 1.3 server connection over conn, like crypto/tls.Server.
// The handshake runs on the first Read or Write, or by Handshake.
//
// Session resumption, 0-RTT and client certificates are not supported.
// Config fields used: Certificates, GetCertificate, NextProtos and CurvePreferences.
func Server(conn net.Conn, config *tls.Config) *Conn {
	return &Conn{Conn: conn, config: config}
}

func (c *Conn) serverHandshake() (err error) {
	hs := serverHandshake{c: c, cfg: c.config}

	return hs.run()
}

func (hs *serverHandshake) run() (err error) {
	c := hs.c

	m, err := hs.readClientHello()
	if err != nil {
		return err
	}

	err = hs.selectParams(m)
	if err != nil {
		return err
	}

	err = hs.s.Reset(hs.suite)
	if err != nil {
		return c.fail(err)
	}

	hs.s.Transcript.Write(m)

	share, ok := hs.clientShare(m)
	if !ok {
		err = hs.sendRetry(m)
		if err != nil {
			return err
		}

		m, err = hs.readClientHello()
		if err != nil {
			return err
		}

		if !hasU16(hs.ch.CipherSuites.Data(m), hs.suite) {
			return c.fail(fmt.Errorf("%w: cipher suite changed after retry", AlertIllegalParameter))
		}

		hs.s.Transcript.Write(m)

		share, ok = hs.clientShare(m)
		if !ok {
			return c.fail(fmt.Errorf("%w: no key share for group %04x after retry", AlertIllegalParameter, hs.group))
		}
	}

	pub, shared, err := ServerKeyShare(hs.group, share)
	if err != nil {
		return c.fail(err)
	}

	sh := hs.appendServerHello(nil, m, pub)
	hs.s.Transcript.Write(sh)

	hs.clientSecret, hs.serverSecret, err = hs.s.HandshakeSecrets(shared)
	if err != nil {
		return c.fail(err)
	}

	flight, err := hs.appendFlight(nil)
	if err != nil {
		return c.fail(err)
	}

	clientApp, serverApp, err := hs.s.ApplicationSecrets()
	if err != nil {
		return c.fail(err)
	}

	err = hs.sendFlight(sh, flight, serverApp)
	if err != nil {
		return err
	}

	err = c.setInKeys(hs.suite, hs.clientSecret)
	if err != nil {
		return err
	}

	err = hs.readFinished()
	if err != nil {
		return err
	}

	err = c.setInKeys(hs.suite, clientApp)
	if err != nil {
		return err
	}

	c.ServerName = hs.serverName
	c.NegotiatedProtocol = hs.alpn

	return nil
}

func (hs *serverHandshake) readClientHello() ([]byte, error) {
	var cs ClientSide

	c := hs.c

	msg, m, err := c.readMessage()
	if err != nil {
		return nil, err
	}
	if msg != MsgClientHello {
		return nil, c.fail(fmt.Errorf("%w: wanted client hello, got %x", AlertUnexpectedMessage, msg))
	}

	_, err = cs.ParseHelloMessage(m, 0, &hs.ch)
	if err != nil {
		return nil, c.fail(fmt.Errorf("%w: client hello: %w", AlertDecodeError, err))
	}

	switch {
	case !slices.Contains(hs.ch.Versions, VerTLS13):
		return nil, c.fail(fmt.Errorf("%w: client doesn't support tls 1.3", AlertProtocolVersion))
	case string(hs.ch.Compression.Data(m)) != "\x00":
		return nil, c.fail(fmt.Errorf("%w: compression methods", AlertIllegalParameter))
	case hs.ch.SupportedGroups.IsZero():
		return nil, c.fail(fmt.Errorf("%w: supported groups", AlertMissingExtension))
	case hs.ch.SignatureAlgorithms.IsZero():
		return nil, c.fail(fmt.Errorf("%w: signature algorithms", AlertMissingExtension))
	}

	return m, nil
}

// selectParams chooses the cipher suite, group, protocol and certificate.
// The group may have no client key share, then HelloRetryRequest asks for it.
func (hs *serverHandshake) selectParams(m []byte) (err error) {
	c := hs.c
	ch := &hs.ch

	for _, s := range serverSuites {
		if hasU16(ch.CipherSuites.Data(m), s) {
			hs.suite = s
			break
		}
	}

	if hs.suite == 0 {
		return c.fail(fmt.Errorf("%w: no mutual cipher suite", AlertHandshakeFailure))
	}

	groups := configGroups(hs.cfg)

	for _, g := range groups {
		if _, ok := hs.clientShare(m, g); ok {
			hs.group = g
			break
		}
	}

	for _, g := range groups {
		if hs.group == 0 && hasU16(ch.SupportedGroups.Data(m), g) {
			hs.group = g
		}
	}

	if hs.group == 0 {
		return c.fail(fmt.Errorf("%w: no mutual group", AlertHandshakeFailure))
	}

	if len(hs.cfg.NextProtos) != 0 && !ch.ALPN.IsZero() {
		for _, p := range hs.cfg.NextProtos {
			if hasALPN(ch.ALPN.Data(m), p) {
				hs.alpn = p
				break
			}
		}

		if hs.alpn == "" {
			return c.fail(fmt.Errorf("%w: no mutual protocol", AlertNoApplicationProtocol))
		}
	}

	hs.serverName = string(ch.ServerName.Data(m))

	hs.cert, err = hs.certificate(m)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", AlertHandshakeFailure, err))
	}

	var ok bool

	hs.signer, ok = hs.cert.PrivateKey.(crypto.Signer)
	if !ok {
		return c.fail(fmt.Errorf("%w: certificate private key is not crypto.Signer", AlertInternalError))
	}

	hs.scheme, ok = signatureScheme(hs.signer.Public(), ch.SignatureAlgorithms.Data(m))
	if !ok {
		return c.fail(fmt.Errorf("%w: no mutual signature scheme", AlertHandshakeFailure))
	}

	return nil
}

func (hs *serverHandshake) certificate(m []byte) (*tls.Certificate, error) {
	cfg := hs.cfg

	if cfg.GetCertificate != nil {
		info := &tls.ClientHelloInfo{
			ServerName:        hs.serverName,
			SupportedVersions: []uint16{uint16(VerTLS13)},
			Conn:              hs.c.Conn,
		}

		for _, s := range list16[SignatureScheme](hs.ch.SignatureAlgorithms.Data(m)) {
			info.SignatureSchemes = append(info.SignatureSchemes, tls.SignatureScheme(s))
		}

		return cfg.GetCertificate(info)
	}

	if len(cfg.Certificates) == 0 {
		return nil, errors.New("no certificates configured")
	}

	for i := range cfg.Certificates {
		leaf := cfg.Certificates[i].Leaf

		if leaf == nil && len(cfg.Certificates[i].Certificate) != 0 {
			leaf, _ = x509.ParseCertificate(cfg.Certificates[i].Certificate[0]) // unparsable certificate doesn't match
		}

		if leaf != nil && leaf.VerifyHostname(hs.serverName) == nil {
			return &cfg.Certificates[i], nil
		}
	}

	return &cfg.Certificates[0], nil
}

// clientShare returns the client key share for the group, the selected one by default.
func (hs *serverHandshake) clientShare(m []byte, group ...KeyGroup) ([]byte, bool) {
	g := hs.group
	if len(group) != 0 {
		g = group[0]
	}

	for _, k := range hs.ch.KeyShare {
		if k.Group == g {
			return k.Data(m), true
		}
	}

	return nil, false
}

// sendRetry sends HelloRetryRequest asking for the key share of the selected group.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
func (hs *serverHandshake) sendRetry(m []byte) error {
	var ss ServerSide

	c := hs.c

	hs.s.HelloRetryRequest()

	b, h, ext := ss.OpenHello(nil, HelloRetryRequestRandom[:], hs.ch.Session.Data(m), hs.suite)

	b, st := ss.OpenExt(b, ExtKeyShare)
	b = appendU16(b, hs.group)
	b = ss.CloseExt(b, st)

	b, st = ss.OpenExt(b, ExtSupportedVersions)
	b = appendU16(b, VerTLS13)
	b = ss.CloseExt(b, st)

	b = ss.CloseHello(b, h, ext)

	hs.s.Transcript.Write(b)

	defer c.wmu.Unlock()
	c.wmu.Lock()

	w := c.appendHandshake(c.buf(), VerTLS12, b)
	w = c.appendChangeCipherSpec(w)

	hs.sentCCS = true

	return c.write(w)
}

func (hs *serverHandshake) appendServerHello(b, m, pub []byte) []byte {
	var ss ServerSide
	var random [32]byte

	_, _ = rand.Read(random[:]) // never fails

	b, h, ext := ss.OpenHello(b, random[:], hs.ch.Session.Data(m), hs.suite)

	b, st := ss.OpenExt(b, ExtSupportedVersions)
	b = appendU16(b, VerTLS13)
	b = ss.CloseExt(b, st)

	b, st = ss.OpenExt(b, ExtKeyShare)
	b = ss.AppendKeyShareEntry(b, hs.group, pub)
	b = ss.CloseExt(b, st)

	return ss.CloseHello(b, h, ext)
}

// appendFlight appends EncryptedExtensions, Certificate, CertificateVerify and Finished
// and writes them into the transcript.
func (hs *serverHandshake) appendFlight(b []byte) ([]byte, error) {
	var ss ServerSide

	st := len(b)

	b, h, ext := ss.OpenEncryptedExtensions(b)

	if hs.alpn != "" {
		b = ss.AppendExtALPN(b, hs.alpn)
	}

	b = ss.CloseEncryptedExtensions(b, h, ext)
	b = ss.AppendCertificate(b, nil, hs.cert.Certificate...)

	hs.s.Transcript.Write(b[st:])
	st = len(b)

	sig, err := sign(hs.signer, hs.scheme, appendSignedContent(nil, true, hs.s.Transcript.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("sign certificate verify: %w", err)
	}

	b = ss.AppendCertificateVerify(b, hs.scheme, sig)

	hs.s.Transcript.Write(b[st:])
	st = len(b)

	fin, err := hs.s.Finished(hs.serverSecret)
	if err != nil {
		return nil, err
	}

	b = ss.AppendFinished(b, fin)

	hs.s.Transcript.Write(b[st:])

	return b, nil
}

// sendFlight sends ServerHello and the encrypted flight and switches Out to the application secret.
func (hs *serverHandshake) sendFlight(sh, flight, serverApp []byte) error {
	c := hs.c

	defer c.wmu.Unlock()
	c.wmu.Lock()

	b := c.appendHandshake(c.buf(), VerTLS12, sh)

	if !hs.sentCCS {
		b = c.appendChangeCipherSpec(b)
	}

	err := c.Out.ResetSecret(hs.suite, hs.serverSecret)
	if err != nil {
		return err
	}

	b = c.appendHandshake(b, VerTLS12, flight)

	err = c.Out.ResetSecret(hs.suite, serverApp)
	if err != nil {
		return err
	}

	return c.write(b)
}

func (hs *serverHandshake) readFinished() error {
	var d Iterator

	c := hs.c

	want, err := hs.s.Finished(hs.clientSecret)
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
		return c.fail(fmt.Errorf("%w: bad client finished", AlertDecryptError))
	}

	return nil
}

// hasALPN reports whether ProtocolNameList contains the protocol.
func hasALPN(list []byte, proto string) bool {
	for i := 0; i < len(list); {
		l := u8[int](list, &i)

		if string(list[i:i+l]) == proto {
			return true
		}

		i += l
	}

	return false
}
