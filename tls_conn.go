package rawtls

import (
	"context"
	"crypto/tls"
	"sync"
)

// Handshake runs the handshake if it's not done yet.
// Read and Write call it themselves.
// Conn made of keys, not by Client or Server, has no handshake to run.
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the handshake if it's not done yet.
// When ctx is done the handshake is interrupted by closing the underlying connection,
// as crypto/tls does. Connection deadlines are not touched.
func (c *Conn) HandshakeContext(ctx context.Context) (err error) {
	if c.config == nil || c.hdone.Load() {
		return c.herr
	}

	defer c.hmu.Unlock()
	c.hmu.Lock()

	if c.hdone.Load() {
		return c.herr
	}

	defer c.interrupt(ctx)()

	c.handshaking = true

	if c.isClient {
		err = c.clientHandshake()
	} else {
		err = c.serverHandshake()
	}

	c.handshaking = false

	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}

	c.herr = err
	c.hdone.Store(true)

	return err
}

// ConnectionState reports the connection in crypto/tls terms.
// Conn made of keys doesn't see the handshake,
// so only ServerName and NegotiatedProtocol set by the caller are reported of it.
func (c *Conn) ConnectionState() tls.ConnectionState {
	defer c.wmu.Unlock()
	c.wmu.Lock()

	return c.state(c.Out.Suite)
}

func (c *Conn) state(suite CipherSuite) tls.ConnectionState {
	return tls.ConnectionState{
		Version:            uint16(VerTLS13),
		HandshakeComplete:  c.config == nil || c.hdone.Load() && c.herr == nil,
		CipherSuite:        uint16(suite),
		ServerName:         c.ServerName,
		NegotiatedProtocol: c.NegotiatedProtocol,
		PeerCertificates:   c.peerCertificates,
		VerifiedChains:     c.verifiedChains,
	}
}

// interrupt closes the underlying connection when ctx is done.
// The returned func stops it and waits for the close to finish if it's started.
func (c *Conn) interrupt(ctx context.Context) func() {
	var wg sync.WaitGroup

	wg.Add(1)

	stop := context.AfterFunc(ctx, func() {
		defer wg.Done()

		_ = c.Conn.Close() // the handshake fails with ctx error
	})

	return func() {
		if stop() {
			wg.Done()
		}

		wg.Wait()
	}
}
