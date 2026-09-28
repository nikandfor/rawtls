package rawtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type (
	handshaker interface {
		net.Conn

		HandshakeContext(ctx context.Context) error
		ConnectionState() tls.ConnectionState
		CloseWrite() error
	}

	// sniffConn records bytes read, to count ClientHello records received by the server.
	sniffConn struct {
		net.Conn

		mu sync.Mutex
		in bytes.Buffer
	}
)

var testCerts struct {
	sync.Mutex

	m map[string]tls.Certificate
}

func TestClientStdServer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		key    string
		client func(*tls.Config)
		server func(*tls.Config)
		hellos int
		alpn   string
		err    error  // client error
		serr   string // server error
	}{
		{name: "ecdsa", key: "ecdsa"},
		{name: "rsa", key: "rsa"},
		{name: "ed25519", key: "ed25519"},
		{
			name:   "alpn",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.NextProtos = []string{"h2", "http/1.1"} },
			server: func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} },
			alpn:   "http/1.1",
		},
		{
			name:   "retry p256",
			key:    "ecdsa",
			server: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} },
			hellos: 2,
		},
		{
			name:   "x25519",
			key:    "ecdsa",
			server: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} },
		},
		{
			name:   "client certificate requested",
			key:    "ecdsa",
			server: func(c *tls.Config) { c.ClientAuth = tls.RequestClientCert },
		},
		{
			name:   "wrong server name",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.ServerName = "wrong.example.com" },
			err:    AlertBadCertificate,
			serr:   "bad certificate",
		},
		{
			name:   "unknown authority",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.RootCAs = x509.NewCertPool() },
			err:    AlertUnknownCA,
			serr:   "unknown certificate authority",
		},
		{
			name:   "insecure skip verify",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.RootCAs = x509.NewCertPool(); c.InsecureSkipVerify = true },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg := testConfigs(t, tc.key)

			if tc.client != nil {
				tc.client(ccfg)
			}
			if tc.server != nil {
				tc.server(scfg)
			}

			a, b := tcpPipe(t)
			sniff := &sniffConn{Conn: b}

			var serr error
			if tc.serr != "" {
				serr = errString(tc.serr)
			}

			testPair(t, Client(a, ccfg), tls.Server(sniff, scfg), tc.alpn, tc.err, serr)
			checkHellos(t, sniff, tc.hellos)
		})
	}
}

func TestStdClientServer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		key    string
		client func(*tls.Config)
		server func(*tls.Config)
		hellos int
		alpn   string
		err    string // client error
		serr   error  // server error
	}{
		{name: "ecdsa", key: "ecdsa"},
		{name: "rsa", key: "rsa"},
		{name: "ed25519", key: "ed25519"},
		{
			name:   "alpn",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.NextProtos = []string{"h2", "http/1.1"} },
			server: func(c *tls.Config) { c.NextProtos = []string{"http/1.1", "h2"} },
			alpn:   "http/1.1",
		},
		{
			// Go client sends X25519 key share whatever the preference order is
			name:   "retry p256",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256} },
			server: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} },
			hellos: 2,
		},
		{
			name:   "p256",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} },
		},
		{
			name: "get certificate",
			key:  "rsa",
			server: func(c *tls.Config) {
				cert := c.Certificates[0]
				c.Certificates = nil
				c.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if info.ServerName != "example.com" {
						return nil, errors.New("unexpected server name")
					}

					return &cert, nil
				}
			},
		},
		{
			name:   "no mutual protocol",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.NextProtos = []string{"h2"} },
			server: func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} },
			err:    "no application protocol",
			serr:   AlertNoApplicationProtocol,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg := testConfigs(t, tc.key)

			if tc.client != nil {
				tc.client(ccfg)
			}
			if tc.server != nil {
				tc.server(scfg)
			}

			a, b := tcpPipe(t)
			sniff := &sniffConn{Conn: b}

			s := Server(sniff, scfg)

			var cerr error
			if tc.err != "" {
				cerr = errString(tc.err)
			}

			testPair(t, tls.Client(a, ccfg), s, tc.alpn, cerr, tc.serr)
			checkHellos(t, sniff, tc.hellos)

			if tc.err == "" && s.ConnectionState().ServerName != "example.com" {
				t.Errorf("server name %q", s.ConnectionState().ServerName)
			}
		})
	}
}

func TestClientServer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		key    string
		client func(*tls.Config)
		server func(*tls.Config)
		hellos int
		alpn   string
	}{
		{name: "ecdsa", key: "ecdsa"},
		{name: "rsa", key: "rsa"},
		{name: "ed25519", key: "ed25519"},
		{
			name:   "alpn",
			key:    "ed25519",
			client: func(c *tls.Config) { c.NextProtos = []string{"h2", "http/1.1"} },
			server: func(c *tls.Config) { c.NextProtos = []string{"h2"} },
			alpn:   "h2",
		},
		{
			name:   "retry p256",
			key:    "ecdsa",
			client: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256} },
			server: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} },
			hellos: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg := testConfigs(t, tc.key)

			if tc.client != nil {
				tc.client(ccfg)
			}
			if tc.server != nil {
				tc.server(scfg)
			}

			a, b := tcpPipe(t)
			sniff := &sniffConn{Conn: b}

			testPair(t, Client(a, ccfg), Server(sniff, scfg), tc.alpn, nil, nil)
			checkHellos(t, sniff, tc.hellos)
		})
	}
}

// testPair runs the handshake, checks the parameters both sides agree on,
// and echoes data from the client through the server.
func testPair(t *testing.T, cli, srv handshaker, alpn string, cerr, serr error) {
	t.Helper()

	var wg sync.WaitGroup
	var serverErr, echoErr error

	defer func() { _ = cli.Close() }()
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wg.Go(func() {
		serverErr = srv.HandshakeContext(ctx)
		if serverErr != nil {
			_ = srv.Close() // unblock the client
			return
		}

		_, echoErr = io.Copy(srv, srv)
		if echoErr == nil {
			echoErr = srv.CloseWrite()
		}
	})

	clientErr := cli.HandshakeContext(ctx)
	if clientErr != nil {
		_ = cli.Close() // unblock the server
	}

	if cerr != nil || serr != nil {
		_ = cli.Close() // the server may be echoing if the handshake wrongly succeeded

		wg.Wait()

		checkErr(t, "client", clientErr, cerr)
		checkErr(t, "server", serverErr, serr)

		return
	}

	if clientErr != nil {
		wg.Wait()
		t.Fatalf("client handshake: %v (server: %v)", clientErr, serverErr)
	}

	data := make([]byte, 100_000)

	for i := range data {
		data[i] = byte(i * 7)
	}

	var writeErr error

	wg.Go(func() {
		_, writeErr = cli.Write(data)
		if writeErr == nil {
			writeErr = cli.CloseWrite()
		}
	})

	got, readErr := io.ReadAll(cli)

	wg.Wait()

	for _, e := range []struct {
		name string
		err  error
	}{{"server handshake", serverErr}, {"echo", echoErr}, {"write", writeErr}, {"read", readErr}} {
		if e.err != nil {
			t.Errorf("%v: %v", e.name, e.err)
		}
	}

	if !bytes.Equal(got, data) {
		t.Errorf("echo: got %d bytes, wanted %d", len(got), len(data))
	}

	cs, ss := cli.ConnectionState(), srv.ConnectionState()

	if cs.Version != tls.VersionTLS13 || ss.Version != tls.VersionTLS13 || cs.CipherSuite != ss.CipherSuite || cs.CipherSuite == 0 {
		t.Errorf("version %x %x suite %x %x", cs.Version, ss.Version, cs.CipherSuite, ss.CipherSuite)
	}
	if cs.NegotiatedProtocol != alpn || ss.NegotiatedProtocol != alpn {
		t.Errorf("alpn %q %q, wanted %q", cs.NegotiatedProtocol, ss.NegotiatedProtocol, alpn)
	}
	if len(cs.PeerCertificates) == 0 {
		t.Errorf("no peer certificates")
	}
}

func checkErr(t *testing.T, side string, got, want error) {
	t.Helper()

	switch w := want.(type) {
	case nil:
		if got != nil {
			t.Errorf("%v: %v", side, got)
		}
	case errString:
		if got == nil || !strings.Contains(got.Error(), string(w)) {
			t.Errorf("%v: wanted error with %q, got %v", side, w, got)
		}
	default:
		if !errors.Is(got, want) {
			t.Errorf("%v: wanted %v, got %v", side, want, got)
		}
	}
}

// errString matches an error by the substring.
type errString string

func (e errString) Error() string { return string(e) }

func checkHellos(t *testing.T, s *sniffConn, want int) {
	t.Helper()

	if want == 0 {
		want = 1
	}

	var d Iterator

	s.mu.Lock()
	b := s.in.Bytes()
	s.mu.Unlock()

	n := 0

	for i := 0; ; {
		tp, _, l, st, err := d.RecordHeader(b, i)
		if err != nil || st+l > len(b) {
			break
		}

		if tp == RecHandshake && l != 0 && HandshakeType(b[st]) == MsgClientHello {
			n++
		}

		i = st + l
	}

	if n != want {
		t.Errorf("client hellos %d, wanted %d", n, want)
	}
}

// tcpPipe returns both ends of a loopback TCP connection.
// net.Pipe has no buffer: two sides writing at once deadlock,
// which TLS peers legitimately do, like a server writing HelloRetryRequest and ChangeCipherSpec separately.
func tcpPipe(t *testing.T) (client, server net.Conn) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = l.Close() }()

	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	server, err = l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	return client, server
}

func testConfigs(t *testing.T, key string) (client, server *tls.Config) {
	t.Helper()

	cert := testCertificate(t, key)

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	client = &tls.Config{
		ServerName: "example.com",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}

	server = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	return client, server
}

func testCertificate(t *testing.T, kind string) tls.Certificate {
	t.Helper()

	defer testCerts.Unlock()
	testCerts.Lock()

	if cert, ok := testCerts.m[kind]; ok {
		return cert
	}

	var key crypto.Signer
	var err error

	switch kind {
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		panic(kind)
	}
	if err != nil {
		t.Fatalf("generate %v key: %v", kind, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}

	if testCerts.m == nil {
		testCerts.m = map[string]tls.Certificate{}
	}

	testCerts.m[kind] = cert

	return cert
}

func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)

	defer c.mu.Unlock()
	c.mu.Lock()

	c.in.Write(p[:n])

	return n, err
}

// The server signs CertificateVerify with a key which is not the certificate's.
func TestBadCertificateVerify(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	for _, tc := range []struct {
		name   string
		client func(net.Conn, *tls.Config) handshaker
		err    error
	}{
		{name: "client", client: func(c net.Conn, cfg *tls.Config) handshaker { return Client(c, cfg) }, err: AlertDecryptError},
		{name: "std client", client: func(c net.Conn, cfg *tls.Config) handshaker { return tls.Client(c, cfg) }, err: errString("verif")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg := testConfigs(t, "ecdsa")

			scfg.Certificates[0].PrivateKey = other

			a, b := tcpPipe(t)

			testPair(t, tc.client(a, ccfg), Server(b, scfg), "", tc.err, AlertDecryptError)
		})
	}
}

func TestHandshakeCanceled(t *testing.T) {
	ccfg, _ := testConfigs(t, "ecdsa")

	a, b := tcpPipe(t)

	defer func() { _ = b.Close() }()

	c := Client(a, ccfg)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := c.HandshakeContext(ctx) // the server never answers
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("wanted %v, got %v", context.DeadlineExceeded, err)
	}

	err = c.Handshake()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("sticky: wanted %v, got %v", context.DeadlineExceeded, err)
	}
}

// Finished of RFC8448 section 3 checked by both sides, correct and tampered.
func TestFinishedRFC8448(t *testing.T) {
	transcript := func(t *testing.T, s *Schedule, msgs ...string) {
		t.Helper()

		err := s.Reset(TLS_AES_128_GCM_SHA256)
		if err != nil {
			t.Fatalf("reset: %v", err)
		}

		for _, m := range msgs {
			s.Transcript.Write(unhex(t, m))
		}
	}

	for _, tc := range []struct {
		name   string
		tamper bool
		err    error
	}{
		{name: "correct"},
		{name: "tampered", tamper: true, err: AlertDecryptError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := func(msg string) io.Reader {
				m := unhex(t, msg)
				if tc.tamper {
					m[len(m)-1] ^= 1
				}

				return bytes.NewReader(appendPlainRecord(nil, RecHandshake, VerTLS12, m))
			}

			cli := clientHandshake{
				c:            &Conn{Conn: &testConn{r: record(rfcServerFinished)}, handshaking: true},
				serverSecret: unhex(t, rfcServerHandshakeSecret),
			}

			transcript(t, &cli.s, rfcClientHello, rfcServerHello, rfcEncryptedExtensions, rfcCertificate, rfcCertificateVerify)

			err := cli.readFinished()
			if !errors.Is(err, tc.err) {
				t.Errorf("client: wanted %v, got %v", tc.err, err)
			}

			srv := serverHandshake{
				c:            &Conn{Conn: &testConn{r: record(rfcClientFinished)}, handshaking: true},
				clientSecret: unhex(t, rfcClientHandshakeSecret),
			}

			transcript(t, &srv.s, rfcClientHello, rfcServerHello, rfcEncryptedExtensions, rfcCertificate, rfcCertificateVerify, rfcServerFinished)

			err = srv.readFinished()
			if !errors.Is(err, tc.err) {
				t.Errorf("server: wanted %v, got %v", tc.err, err)
			}
		})
	}
}

// The handshake leaves connection deadlines as the caller set them.
func TestHandshakeKeepsDeadline(t *testing.T) {
	ccfg, scfg := testConfigs(t, "ecdsa")

	a, b := tcpPipe(t)
	s := tls.Server(b, scfg)
	c := Client(a, ccfg)

	var wg sync.WaitGroup

	defer wg.Wait()
	defer func() { _ = s.Close() }()
	defer func() { _ = c.Close() }()

	wg.Go(func() {
		if s.Handshake() == nil {
			_, _ = io.Copy(io.Discard, s) // never answers
		}
	})

	err := a.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = c.HandshakeContext(ctx)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	_, err = c.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read: wanted %v, got %v", os.ErrDeadlineExceeded, err)
	}
}
