package rawtls

// keyUpdateAfter is the number of records Write sends under the same keys.
// It's below the AES-GCM limit of 2^24.5 records.
// ChaCha20-Poly1305 has no practical limit, the same number is used for simplicity.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-5.5
const keyUpdateAfter = 1 << 24

const writeBufSize = 5 + MaxCiphertext + 0x40 // data record with KeyUpdate record in front of it

func (c *Conn) Write(p []byte) (n int, err error) {
	err = c.Handshake() // before the write lock, the handshake takes it
	if err != nil {
		return 0, err
	}

	defer c.wmu.Unlock()
	c.wmu.Lock()

	for n < len(p) {
		if c.werr != nil {
			return n, c.werr
		}

		m := min(len(p)-n, MaxPlaintext)
		b := c.buf()

		if c.Out.Seq >= keyUpdateAfter {
			b, err = c.appendKeyUpdate(b, false)
			if err != nil {
				return n, err
			}
		}

		b = c.appendRecord(b, RecAppData, p[n:n+m])

		err = c.write(b)
		if err != nil {
			return n, err
		}

		n += m
	}

	return n, nil
}

// UpdateKeys sends KeyUpdate and moves Out to the next traffic secret.
// If requestPeer is set, the peer is asked to update its keys too.
// Write updates keys itself before they reach the usage limit.
func (c *Conn) UpdateKeys(requestPeer bool) error {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	return c.updateKeys(requestPeer)
}

// CloseWrite sends close_notify. The underlying connection is left open.
func (c *Conn) CloseWrite() error {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	return c.closeWrite()
}

// Close sends close_notify and closes the underlying connection.
func (c *Conn) Close() (err error) {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	defer func() {
		e := c.Conn.Close()
		if err == nil && e != nil {
			err = e
		}
	}()

	return c.closeWrite()
}

func (c *Conn) closeWrite() error {
	if c.werr != nil {
		return nil
	}

	err := c.writeAlert(AlertCloseNotify)
	if err != nil {
		return err
	}

	c.werr = ErrShutdown

	return nil
}

func (c *Conn) updateKeys(requestPeer bool) error {
	if c.werr != nil {
		return c.werr
	}

	b, err := c.appendKeyUpdate(c.buf(), requestPeer)
	if err != nil {
		return err
	}

	return c.write(b)
}

// appendKeyUpdate appends KeyUpdate record and moves Out to the next traffic secret.
func (c *Conn) appendKeyUpdate(b []byte, requestPeer bool) ([]byte, error) {
	if len(c.Out.secret) == 0 {
		return b, errUpdateNoSecret
	}

	var e Emitter
	var msg [5]byte

	v := byte(0) // update_not_requested
	if requestPeer {
		v = 1
	}

	m, st := e.OpenHandshake(msg[:0], MsgKeyUpdate)
	m = appendU8(m, v)
	m = e.CloseHandshake(m, st)

	b = c.appendRecord(b, RecHandshake, m)

	return b, c.Out.Update()
}

func (c *Conn) writeAlert(a AlertDescription) error {
	level := AlertLevelFatal
	if a == AlertCloseNotify || a == AlertUserCanceled {
		level = AlertLevelWarning
	}

	return c.writeRecord(RecAlert, []byte{byte(level), byte(a)})
}

func (c *Conn) writeRecord(tp ContentType, data []byte) error {
	if c.werr != nil {
		return c.werr
	}

	b := c.appendRecord(c.buf(), tp, data)

	return c.write(b)
}

// appendHandshake appends handshake messages as records of at most MaxPlaintext.
// Before Out keys are set the records are plaintext with legacy version ver.
func (c *Conn) appendHandshake(b []byte, ver ProtocolVersion, msgs []byte) []byte {
	for len(msgs) != 0 {
		m := min(len(msgs), MaxPlaintext)

		if c.Out.aead == nil {
			b = appendPlainRecord(b, RecHandshake, ver, msgs[:m])
		} else {
			b = c.appendRecord(b, RecHandshake, msgs[:m])
		}

		msgs = msgs[m:]
	}

	return b
}

// appendChangeCipherSpec appends ChangeCipherSpec record of the middlebox compatibility mode.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#appendix-D.4
func (c *Conn) appendChangeCipherSpec(b []byte) []byte {
	return appendPlainRecord(b, RecChangeCipherSpec, VerTLS12, []byte{1})
}

// setOutKeys switches outgoing records to the traffic secret.
func (c *Conn) setOutKeys(suite CipherSuite, secret []byte) error {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	return c.Out.ResetSecret(suite, secret)
}

// appendRecord appends protected record, or plaintext one before Out keys are set.
func (c *Conn) appendRecord(b []byte, tp ContentType, data []byte) []byte {
	var e Emitter

	if c.Out.aead == nil {
		return appendPlainRecord(b, tp, VerTLS12, data)
	}

	b, st := e.OpenRecord(b, RecAppData, VerTLS12)
	b = append(b, data...)

	return c.Out.Seal(b, st, tp, 0)
}

// write writes records to the connection.
// A failed write may leave a partial record on the wire, so write errors are sticky.
func (c *Conn) write(b []byte) error {
	c.wbuf = b[:0]

	_, err := c.Conn.Write(b)
	if err != nil {
		c.werr = err
	}

	return err
}

func (c *Conn) buf() []byte {
	if cap(c.wbuf) < writeBufSize {
		c.wbuf = make([]byte, 0, writeBufSize)
	}

	return c.wbuf[:0]
}

func appendPlainRecord(b []byte, tp ContentType, ver ProtocolVersion, data []byte) []byte {
	var e Emitter

	b, st := e.OpenRecord(b, tp, ver)
	b = append(b, data...)

	return e.CloseRecord(b, st)
}
