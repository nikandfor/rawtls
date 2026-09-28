package rawtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type (
	// Conn is a TLS 1.3 connection.
	// It's made by Client or Server, which run the handshake,
	// or set up past the handshake by resetting In and Out keys, possibly in the middle of a session:
	//
	//	c := &Conn{Conn: nc}
	//	err = c.In.ResetSecret(suite, peerTrafficSecret)
	//	err = c.Out.ResetSecret(suite, ownTrafficSecret)
	//
	// Read and Write can be called concurrently.
	// Keys must come from ResetSecret for KeyUpdate to work.
	Conn struct {
		net.Conn

		In  Keys // incoming records, used by Read
		Out Keys // outgoing records, guarded by the write lock once in use

		// AllowTruncation makes EOF without close_notify read as io.EOF.
		// By default it's io.ErrUnexpectedEOF, as the data may be cut by an attacker.
		AllowTruncation bool

		ServerName         string // reported by ConnectionState
		NegotiatedProtocol string // ALPN protocol, reported by ConnectionState

		config   *tls.Config // set by Client and Server
		isClient bool

		hmu   sync.Mutex
		hdone atomic.Bool
		herr  error

		peerCertificates []*x509.Certificate
		verifiedChains   [][]*x509.Certificate

		wmu  sync.Mutex
		wbuf []byte
		werr error // sticky: writer is closed or broken

		// end of wmu

		rbuf      []byte
		i, end    int // raw records in rbuf
		pst, pend int // application data in rbuf not yet read

		hbuf []byte // handshake messages
		hi   int    // start of unread handshake data in hbuf
		rerr error  // sticky

		// handshaking accepts plaintext records before In keys are set and ChangeCipherSpec,
		// handshake messages are taken with readMessage.
		handshaking bool
	}
)

// MaxHandshake is the longest handshake message accepted.
const MaxHandshake = 1 << 16

const readBufSize = 2 * (5 + MaxCiphertext)

var errUpdateNoSecret = fmt.Errorf("%w: key update: keys are set without traffic secret", ErrUnsupported)

func (c *Conn) Read(p []byte) (n int, err error) {
	err = c.Handshake()
	if err != nil {
		return 0, err
	}

	for c.pst == c.pend && len(p) != 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}

		err = c.readRecord()
		if err != nil {
			return 0, err
		}
	}

	n = copy(p, c.rbuf[c.pst:c.pend])
	c.pst += n

	return n, nil
}

// NetConn returns the underlying connection.
func (c *Conn) NetConn() net.Conn { return c.Conn }

func (c *Conn) readRecord() (err error) {
	var d Iterator

	err = c.more(5)
	if errors.Is(err, io.EOF) && !c.AllowTruncation { // EOF without close_notify
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return c.readErr(err)
	}

	outer, _, l, _, _ := d.RecordHeader(c.rbuf[:c.end], c.i) // the header is read above

	switch {
	case outer == RecAppData && c.In.aead != nil:
	case !c.handshaking: // everything is protected past the handshake
		return c.fail(AlertUnexpectedMessage)
	case outer == RecChangeCipherSpec:
	case (outer == RecHandshake || outer == RecAlert) && c.In.aead == nil:
	default:
		return c.fail(AlertUnexpectedMessage)
	}

	if l > MaxCiphertext || (outer != RecAppData && l > MaxPlaintext) {
		return c.fail(AlertRecordOverflow)
	}

	err = c.more(5 + l)
	if err != nil {
		return c.readErr(err)
	}

	st := c.i + 5
	c.i = st + l

	data := c.rbuf[st:c.i]
	tp := outer

	switch outer {
	case RecChangeCipherSpec: // compatibility mode, dropped
		if l != 1 || data[0] != 1 {
			return c.fail(AlertUnexpectedMessage)
		}

		return nil
	case RecAppData:
		data, tp, err = c.In.Open(c.rbuf[:c.i], st)
		if err != nil {
			return c.fail(err)
		}
	}

	if c.hi != len(c.hbuf) && tp != RecHandshake {
		return c.fail(AlertUnexpectedMessage)
	}

	switch tp {
	case RecAppData:
		if c.handshaking {
			return c.fail(AlertUnexpectedMessage)
		}

		c.pst = st // Open is in place
		c.pend = st + len(data)

		return nil
	case RecAlert:
		return c.processAlert(data)
	case RecHandshake:
		return c.processHandshake(data)
	}

	return c.fail(AlertUnexpectedMessage)
}

func (c *Conn) processAlert(data []byte) error {
	if len(data) != 2 {
		return c.fail(AlertDecodeError)
	}

	switch a := AlertDescription(data[1]); a {
	case AlertCloseNotify:
		c.rerr = io.EOF
	case AlertUserCanceled:
		return nil
	default:
		c.rerr = fmt.Errorf("remote: %w", a)
	}

	return c.rerr
}

func (c *Conn) processHandshake(data []byte) error {
	if len(data) == 0 {
		return c.fail(AlertUnexpectedMessage)
	}

	c.hbuf = append(c.hbuf, data...)

	if c.handshaking { // messages are taken by readMessage
		return nil
	}

	for {
		msg, m, err := c.nextMessage()
		if err != nil {
			return err
		}
		if m == nil {
			break
		}

		switch msg {
		case MsgNewSessionTicket:
			// resumption is not supported, tickets are dropped
		case MsgKeyUpdate:
			if c.hi != len(c.hbuf) { // keys change after it, so it must end the record
				return c.fail(AlertUnexpectedMessage)
			}

			err = c.processKeyUpdate(m[4:])
			if err != nil {
				return err
			}
		default:
			return c.fail(AlertUnexpectedMessage)
		}
	}

	c.compactHandshake()

	return nil
}

// readMessage reads the next handshake message, header included.
// The message is valid until the next call.
func (c *Conn) readMessage() (msg HandshakeType, m []byte, err error) {
	for {
		msg, m, err = c.nextMessage()
		if err != nil || m != nil {
			return msg, m, err
		}

		c.compactHandshake()

		err = c.readRecord()
		if err != nil {
			return 0, nil, err
		}
	}
}

// nextMessage takes the next complete handshake message from hbuf, header included.
// The message is nil if it's not complete yet.
func (c *Conn) nextMessage() (msg HandshakeType, m []byte, err error) {
	var d Iterator

	msg, l, st, err := d.HandshakeHeader(c.hbuf, c.hi)
	if err != nil { // the header is split across records
		return 0, nil, nil
	}

	if l > MaxHandshake {
		return 0, nil, c.fail(AlertUnexpectedMessage)
	}
	if st+l > len(c.hbuf) {
		return 0, nil, nil
	}

	m = c.hbuf[c.hi : st+l]
	c.hi = st + l

	return msg, m, nil
}

func (c *Conn) compactHandshake() {
	n := copy(c.hbuf, c.hbuf[c.hi:])

	c.hbuf = c.hbuf[:n]
	c.hi = 0
}

// setInKeys switches incoming records to the traffic secret.
// Handshake messages must not span key changes.
func (c *Conn) setInKeys(suite CipherSuite, secret []byte) error {
	if c.hi != len(c.hbuf) {
		return c.fail(AlertUnexpectedMessage)
	}

	err := c.In.ResetSecret(suite, secret)
	if err != nil {
		return c.fail(err)
	}

	return nil
}

// processKeyUpdate handles KeyUpdate.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
func (c *Conn) processKeyUpdate(body []byte) error {
	if len(body) != 1 {
		return c.fail(AlertDecodeError)
	}
	if body[0] > 1 {
		return c.fail(AlertIllegalParameter)
	}

	if len(c.In.secret) == 0 {
		return c.fail(errUpdateNoSecret)
	}

	err := c.In.Update()
	if err != nil {
		return c.fail(err)
	}

	if body[0] == 0 { // update_not_requested
		return nil
	}

	err = c.respondKeyUpdate()
	if err != nil {
		return c.fail(err)
	}

	return nil
}

func (c *Conn) respondKeyUpdate() error {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	if c.werr != nil { // the writer is closed, nothing to protect anymore
		return nil
	}

	return c.updateKeys(false)
}

// fail sends the alert for err to the peer and makes err sticky for Read.
// Errors which are not alerts are reported as internal_error.
func (c *Conn) fail(err error) error {
	a := AlertInternalError
	_ = errors.As(err, &a)

	c.rerr = err

	defer c.wmu.Unlock()
	c.wmu.Lock()

	_ = c.writeAlert(a) // best effort, the connection is broken anyway

	if c.werr == nil {
		c.werr = err
	}

	return err
}

// readErr makes EOF sticky.
// Other network errors, like timeouts, leave the Conn usable.
func (c *Conn) readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		c.rerr = err
	}

	return err
}

// more makes n bytes of the current record available in rbuf[c.i:].
// EOF with nothing of the record read is io.EOF, in the middle of it is io.ErrUnexpectedEOF.
func (c *Conn) more(n int) error {
	if len(c.rbuf) < readBufSize {
		c.rbuf = make([]byte, readBufSize)
	}

	if c.i > len(c.rbuf)/2 || c.i+n > len(c.rbuf) {
		copy(c.rbuf, c.rbuf[c.i:c.end])

		c.end -= c.i
		c.i = 0
	}

	for c.end-c.i < n {
		m, err := c.Conn.Read(c.rbuf[c.end:])
		c.end += m

		switch {
		case err == nil || c.end-c.i >= n:
		case errors.Is(err, io.EOF) && c.end == c.i:
			return io.EOF
		case errors.Is(err, io.EOF):
			return io.ErrUnexpectedEOF
		default:
			return err
		}
	}

	return nil
}
