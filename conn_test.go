package rawtls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/iotest"
)

type testConn struct {
	net.Conn // nil, stubs the rest

	r io.Reader
	w bytes.Buffer

	writes int
}

// Server side of RFC8448 section 3, constructed past the handshake.
// It reads the client's records and must write exactly the server's records.
func TestConnRFC8448(t *testing.T) {
	in := cat(unhex(t, rfcClientAppDataRecord), unhex(t, rfcClientCloseNotifyRecord))
	out := cat(unhex(t, rfcServerAppDataRecord), unhex(t, rfcServerCloseNotifyRecord))

	for _, tc := range []struct {
		name string
		r    io.Reader
	}{
		{name: "whole", r: bytes.NewReader(in)},
		{name: "byte by byte", r: iotest.OneByteReader(bytes.NewReader(in))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := &testConn{r: tc.r}
			c := &Conn{Conn: nc}

			resetKeys(t, &c.In, TLS_AES_128_GCM_SHA256, nil, nil, unhex(t, rfcClientSecret), 0)
			resetKeys(t, &c.Out, TLS_AES_128_GCM_SHA256, nil, nil, unhex(t, rfcServerSecret), 1) // NewSessionTicket was sent

			data, err := io.ReadAll(c)
			if err != nil {
				t.Errorf("read: %v", err)
			}
			if !bytes.Equal(data, unhex(t, rfcAppData)) {
				t.Errorf("read\n got  %x\n want %s", data, rfcAppData)
			}

			_, err = c.Write(data)
			if err != nil {
				t.Errorf("write: %v", err)
			}

			err = c.Close()
			if err != nil {
				t.Errorf("close: %v", err)
			}

			if got := nc.w.Bytes(); !bytes.Equal(got, out) {
				t.Errorf("written: differs at %#x\n got  %x\n want %x", diffAt(got, out), got, out)
			}
		})
	}
}

func TestConnHandshakeMessages(t *testing.T) {
	var e Emitter

	wc := &testConn{}
	w := &Conn{Conn: wc}

	testKeys(t, &w.Out, 1)

	ticket, st := e.OpenHandshake(nil, MsgNewSessionTicket)
	ticket = append(ticket, bytes.Repeat([]byte{0xaa}, 20)...)
	ticket = e.CloseHandshake(ticket, st)

	update, st := e.OpenHandshake(nil, MsgKeyUpdate)
	update = append(update, 0) // update_not_requested
	update = e.CloseHandshake(update, st)

	write := func(err error) {
		t.Helper()

		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write(w.writeRecord(RecHandshake, ticket[:3]))                       // split in the header
	write(w.writeRecord(RecHandshake, cat(ticket[3:10])))                // and in the body
	write(w.writeRecord(RecHandshake, cat(ticket[10:], ticket, update))) // coalesced, KeyUpdate ends the record
	write(w.Out.Update())
	_, err := w.Write([]byte("after update"))
	write(err)
	write(w.CloseWrite())

	rc := &testConn{r: bytes.NewReader(wc.w.Bytes())}
	r := &Conn{Conn: rc}

	testKeys(t, &r.In, 1)
	testKeys(t, &r.Out, 2)

	data, err := io.ReadAll(r)
	if err != nil || string(data) != "after update" {
		t.Errorf("read %q %v, wanted %q", data, err, "after update")
	}

	if !bytes.Equal(r.In.secret, w.Out.secret) {
		t.Errorf("reader keys are not updated")
	}
	if rc.w.Len() != 0 {
		t.Errorf("reader wrote %x, wanted nothing", rc.w.Bytes())
	}
}

func TestConnKeyUpdateRequested(t *testing.T) {
	wc := &testConn{}
	w := &Conn{Conn: wc}

	testKeys(t, &w.Out, 1)

	err := w.UpdateKeys(true)
	if err != nil {
		t.Fatalf("update keys: %v", err)
	}

	_, err = w.Write([]byte("data"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	err = w.CloseWrite()
	if err != nil {
		t.Fatalf("close write: %v", err)
	}

	rc := &testConn{r: bytes.NewReader(wc.w.Bytes())}
	r := &Conn{Conn: rc}

	testKeys(t, &r.In, 1)
	testKeys(t, &r.Out, 2)

	var old Keys

	testKeys(t, &old, 2)

	data, err := io.ReadAll(r)
	if err != nil || string(data) != "data" {
		t.Errorf("read %q %v, wanted %q", data, err, "data")
	}

	p, tp, err := old.Open(rc.w.Bytes(), 5)
	if err != nil || tp != RecHandshake || !bytes.Equal(p, []byte{byte(MsgKeyUpdate), 0, 0, 1, 0}) {
		t.Errorf("response %x type %x %v, wanted KeyUpdate(update_not_requested)", p, tp, err)
	}

	err = old.Update()
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	if !bytes.Equal(r.Out.secret, old.secret) || r.Out.Seq != 0 {
		t.Errorf("writer keys are not updated")
	}
}

func TestConnPipe(t *testing.T) {
	a, b := net.Pipe()

	ca := &Conn{Conn: a}
	cb := &Conn{Conn: b}

	testKeys(t, &ca.Out, 1)
	testKeys(t, &cb.In, 1)
	testKeys(t, &cb.Out, 2)
	testKeys(t, &ca.In, 2)

	dataA := make([]byte, 100_000)
	dataB := make([]byte, 70_000)

	for i := range dataA {
		dataA[i] = byte(i * 7)
	}
	for i := range dataB {
		dataB[i] = byte(i * 13)
	}

	writeAll := func(c *Conn, data []byte, update bool) error {
		half := len(data) / 2

		_, err := c.Write(data[:half])
		if err != nil {
			return err
		}

		if update {
			err = c.UpdateKeys(true)
			if err != nil {
				return err
			}
		}

		_, err = c.Write(data[half:])
		if err != nil {
			return err
		}

		return c.CloseWrite()
	}

	var gotA, gotB []byte
	var errs [4]error
	var wg sync.WaitGroup

	wg.Go(func() { errs[0] = writeAll(ca, dataA, true) })
	wg.Go(func() { errs[1] = writeAll(cb, dataB, false) })
	wg.Go(func() { gotB, errs[2] = io.ReadAll(ca) })
	wg.Go(func() { gotA, errs[3] = io.ReadAll(cb) })

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	if !bytes.Equal(gotA, dataA) || !bytes.Equal(gotB, dataB) {
		t.Errorf("data mismatch: a %d/%d b %d/%d", len(gotA), len(dataA), len(gotB), len(dataB))
	}

	if !bytes.Equal(ca.Out.secret, cb.In.secret) || !bytes.Equal(cb.Out.secret, ca.In.secret) {
		t.Errorf("keys diverged")
	}

	_ = ca.Close()
	_ = cb.Close()
}

func TestConnReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream func(t *testing.T, w *Conn, b *bytes.Buffer) []byte
		err    error
		sent   bool // the alert for err is sent to the peer
		raw    bool // reader keys have no traffic secret

		allowTruncation bool
	}{{
		name: "tampered",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_, _ = w.Write([]byte("data"))
			s := b.Bytes()
			s[len(s)-1] ^= 1
			return s
		},
		err:  AlertBadRecordMAC,
		sent: true,
	}, {
		name: "unprotected change cipher spec",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			return []byte{byte(RecChangeCipherSpec), 3, 3, 0, 1, 1}
		},
		err:  AlertUnexpectedMessage,
		sent: true,
	}, {
		name: "record overflow",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			return []byte{byte(RecAppData), 3, 3, 0xff, 0xff}
		},
		err:  AlertRecordOverflow,
		sent: true,
	}, {
		name: "empty handshake record",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, nil)
			return b.Bytes()
		},
		err:  AlertUnexpectedMessage,
		sent: true,
	}, {
		name: "interleaved handshake",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, []byte{byte(MsgNewSessionTicket), 0})
			_, _ = w.Write([]byte("data"))
			return b.Bytes()
		},
		err:  AlertUnexpectedMessage,
		sent: true,
	}, {
		name: "key update not at record end",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, []byte{byte(MsgKeyUpdate), 0, 0, 1, 0, byte(MsgNewSessionTicket)})
			return b.Bytes()
		},
		err:  AlertUnexpectedMessage,
		sent: true,
	}, {
		name: "bad key update",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, []byte{byte(MsgKeyUpdate), 0, 0, 1, 2})
			return b.Bytes()
		},
		err:  AlertIllegalParameter,
		sent: true,
	}, {
		name: "unexpected handshake message",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, []byte{byte(MsgFinished), 0, 0, 0})
			return b.Bytes()
		},
		err:  AlertUnexpectedMessage,
		sent: true,
	}, {
		name: "key update without secret",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeRecord(RecHandshake, []byte{byte(MsgKeyUpdate), 0, 0, 1, 0})
			return b.Bytes()
		},
		err:  ErrUnsupported,
		sent: true,
		raw:  true,
	}, {
		name: "remote alert",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_ = w.writeAlert(AlertHandshakeFailure)
			return b.Bytes()
		},
		err: AlertHandshakeFailure,
	}, {
		name: "no close notify",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_, _ = w.Write([]byte("data"))
			return b.Bytes()
		},
		err: io.ErrUnexpectedEOF,
	}, {
		name: "no close notify allowed",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_, _ = w.Write([]byte("data"))
			return b.Bytes()
		},
		err:             nil, // io.ReadAll hides io.EOF
		allowTruncation: true,
	}, {
		name: "truncated",
		stream: func(t *testing.T, w *Conn, b *bytes.Buffer) []byte {
			_, _ = w.Write([]byte("data"))
			return b.Bytes()[:b.Len()-1]
		},
		err: io.ErrUnexpectedEOF,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			wc := &testConn{}
			w := &Conn{Conn: wc}

			testKeys(t, &w.Out, 1)

			rc := &testConn{r: bytes.NewReader(tc.stream(t, w, &wc.w))}
			r := &Conn{Conn: rc}

			testKeys(t, &r.In, 1)
			testKeys(t, &r.Out, 2)

			if tc.raw {
				r.In.secret = nil
			}

			r.AllowTruncation = tc.allowTruncation

			for i := range 2 { // errors are sticky
				_, err := io.ReadAll(r)
				if !errors.Is(err, tc.err) {
					t.Errorf("read %d: wanted %v, got %v", i, tc.err, err)
				}
			}

			if !tc.sent {
				if rc.w.Len() != 0 {
					t.Errorf("sent %x, wanted nothing", rc.w.Bytes())
				}

				return
			}

			var k Keys

			testKeys(t, &k, 2)

			alert := AlertInternalError
			_ = errors.As(tc.err, &alert)

			p, tp, err := k.Open(rc.w.Bytes(), 5)
			if err != nil || tp != RecAlert || len(p) != 2 || AlertDescription(p[1]) != alert {
				t.Errorf("sent %x type %x %v, wanted alert %v", p, tp, err, alert)
			}

			_, err = r.Write([]byte("more"))
			if err == nil {
				t.Errorf("write after fatal alert succeeded")
			}
		})
	}
}

func TestConnAutoKeyUpdate(t *testing.T) {
	wc := &testConn{}
	w := &Conn{Conn: wc}

	testKeys(t, &w.Out, 1)
	w.Out.Seq = keyUpdateAfter - 1

	data := make([]byte, MaxPlaintext+10) // the second record goes over the limit

	for i := range data {
		data[i] = byte(i * 7)
	}

	_, err := w.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if wc.writes != 2 {
		t.Errorf("writes %d, wanted 2: KeyUpdate goes in the same write as the data after it", wc.writes)
	}
	if w.Out.Seq != 1 {
		t.Errorf("seq %d, wanted 1: one record under the updated keys", w.Out.Seq)
	}

	err = w.CloseWrite()
	if err != nil {
		t.Fatalf("close write: %v", err)
	}

	rc := &testConn{r: bytes.NewReader(wc.w.Bytes())}
	r := &Conn{Conn: rc}

	testKeys(t, &r.In, 1)
	testKeys(t, &r.Out, 2)
	r.In.Seq = keyUpdateAfter - 1

	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("read %d bytes %v, wanted %d", len(got), err, len(data))
	}

	if !bytes.Equal(r.In.secret, w.Out.secret) {
		t.Errorf("reader keys are not updated")
	}
}

func TestConnState(t *testing.T) {
	c := &Conn{
		ServerName:         "example.com",
		NegotiatedProtocol: "h2",
	}

	resetKeys(t, &c.Out, TLS_AES_256_GCM_SHA384, nil, nil, bytes.Repeat([]byte{1}, 48), 0)

	s := c.ConnectionState()

	if s.Version != tls.VersionTLS13 || !s.HandshakeComplete || s.CipherSuite != tls.TLS_AES_256_GCM_SHA384 ||
		s.ServerName != "example.com" || s.NegotiatedProtocol != "h2" {
		t.Errorf("state %+v", s)
	}
}

func testKeys(t *testing.T, k *Keys, seed byte) {
	t.Helper()

	resetKeys(t, k, TLS_AES_128_GCM_SHA256, nil, nil, bytes.Repeat([]byte{seed}, 32), 0)
}

func (c *testConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *testConn) Write(p []byte) (int, error) { c.writes++; return c.w.Write(p) }
func (c *testConn) Close() error                { return nil }

func cat(bs ...[]byte) (r []byte) {
	for _, b := range bs {
		r = append(r, b...)
	}

	return r
}

// Client side of RFC8448 section 3 handshake records.
// ChangeCipherSpec is not in the trace, it's added to check it's dropped.
func TestConnHandshakeRecordsRFC8448(t *testing.T) {
	in := cat(
		appendPlainRecord(nil, RecHandshake, VerTLS12, unhex(t, rfcServerHello)),
		(&Conn{}).AppendChangeCipherSpec(nil),
		unhex(t, rfcServerHandshakeRecord),
	)

	for _, tc := range []struct {
		name string
		r    io.Reader
	}{
		{name: "whole", r: bytes.NewReader(in)},
		{name: "byte by byte", r: iotest.OneByteReader(bytes.NewReader(in))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{Conn: &testConn{r: tc.r}, handshaking: true}

			readMessage(t, c, MsgServerHello, rfcServerHello)

			err := c.SetInKeys(TLS_AES_128_GCM_SHA256, unhex(t, rfcServerHandshakeSecret))
			if err != nil {
				t.Fatalf("set keys: %v", err)
			}

			readMessage(t, c, MsgEncryptedExtensions, rfcEncryptedExtensions)
			readMessage(t, c, MsgCertificate, rfcCertificate)
			readMessage(t, c, MsgCertificateVerify, rfcCertificateVerify)
			readMessage(t, c, MsgFinished, rfcServerFinished)
		})
	}

	wc := &testConn{}
	c := &Conn{Conn: wc, handshaking: true}

	b := c.AppendHandshake(c.buf(), VerTLS10, unhex(t, rfcClientHello))

	err := c.SetOutKeys(TLS_AES_128_GCM_SHA256, unhex(t, rfcClientHandshakeSecret))
	if err != nil {
		t.Fatalf("set keys: %v", err)
	}

	b = c.AppendHandshake(b, VerTLS12, unhex(t, rfcClientFinished))

	err = c.write(b)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	want := cat([]byte{byte(RecHandshake), 3, 1, 0, 0xc4}, unhex(t, rfcClientHello), unhex(t, rfcClientFinishedRecord))

	if got := wc.w.Bytes(); !bytes.Equal(got, want) || wc.writes != 1 {
		t.Errorf("written %d times: differs at %#x\n got  %x\n want %x", wc.writes, diffAt(got, want), got, want)
	}
}

func TestConnHandshakeFragmented(t *testing.T) {
	var e Emitter

	wc := &testConn{}
	w := &Conn{Conn: wc, handshaking: true}

	testKeys(t, &w.Out, 1)

	cert := make([]byte, 40_000)

	for i := range cert {
		cert[i] = byte(i * 7)
	}

	msg := e.AppendCertificate(nil, nil, cert)

	err := w.write(w.AppendHandshake(w.buf(), VerTLS12, msg))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	r := &Conn{Conn: &testConn{r: bytes.NewReader(wc.w.Bytes())}, handshaking: true}

	testKeys(t, &r.In, 1)

	tp, m, err := r.readMessage()
	if err != nil || tp != MsgCertificate || !bytes.Equal(m, msg) {
		t.Errorf("read %x %d bytes %v, wanted certificate %d bytes", tp, len(m), err, len(msg))
	}

	if r.In.Seq != 3 {
		t.Errorf("seq %d, wanted 3 records", r.In.Seq)
	}
}

func TestConnHandshakeErrors(t *testing.T) {
	var e Emitter

	for _, tc := range []struct {
		name   string
		stream []byte
		keys   bool // switch In keys after the first message
		err    error
	}{{
		name: "plaintext alert",
		stream: appendPlainRecord(nil, RecAlert, VerTLS12,
			[]byte{byte(AlertLevelFatal), byte(AlertHandshakeFailure)}),
		err: AlertHandshakeFailure,
	}, {
		name:   "bad change cipher spec",
		stream: appendPlainRecord(nil, RecChangeCipherSpec, VerTLS12, []byte{2}),
		err:    AlertUnexpectedMessage,
	}, {
		name:   "application data before keys",
		stream: appendPlainRecord(nil, RecAppData, VerTLS12, []byte("data")),
		err:    AlertUnexpectedMessage,
	}, {
		name:   "plaintext record overflow",
		stream: []byte{byte(RecHandshake), 3, 3, 0x40, 0x01},
		err:    AlertRecordOverflow,
	}, {
		name: "message spans key change",
		stream: appendPlainRecord(nil, RecHandshake, VerTLS12,
			cat(e.AppendFinished(nil, []byte{1}), []byte{byte(MsgFinished), 0})),
		keys: true,
		err:  AlertUnexpectedMessage,
	}, {
		name: "message too long",
		stream: appendPlainRecord(nil, RecHandshake, VerTLS12,
			[]byte{byte(MsgCertificate), 0x01, 0, 1}),
		err: AlertUnexpectedMessage,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{Conn: &testConn{r: bytes.NewReader(tc.stream)}, handshaking: true}

			_, _, err := c.readMessage()

			if tc.keys {
				if err != nil {
					t.Fatalf("read: %v", err)
				}

				err = c.SetInKeys(TLS_AES_128_GCM_SHA256, bytes.Repeat([]byte{1}, 32))
			}

			if !errors.Is(err, tc.err) {
				t.Errorf("wanted %v, got %v", tc.err, err)
			}
		})
	}
}

func readMessage(t *testing.T, c *Conn, tp HandshakeType, want string) {
	t.Helper()

	got, m, err := c.readMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	if got != tp || !bytes.Equal(m, unhex(t, want)) {
		t.Errorf("message %x, wanted %x\n got  %x\n want %s", got, tp, m, want)
	}
}
