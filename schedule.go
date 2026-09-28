package rawtls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"fmt"
	"hash"
)

type (
	// Schedule is TLS 1.3 key schedule without pre-shared keys.
	//
	//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
	Schedule struct {
		Suite CipherSuite

		// Transcript is the running hash of the handshake messages, headers included.
		// The caller writes every message in order.
		Transcript hash.Hash

		h      func() hash.Hash
		secret []byte // early, then handshake, then master secret
	}
)

// Reset starts the schedule for the suite from the early secret.
func (s *Schedule) Reset(suite CipherSuite) (err error) {
	h := suiteHash(suite)
	if h == nil {
		return fmt.Errorf("%w: cipher suite %04x", ErrUnsupported, suite)
	}

	s.Suite = suite
	s.Transcript = h()
	s.h = h

	s.secret, err = hkdf.Extract(h, make([]byte, s.Transcript.Size()), nil)

	return err
}

// HandshakeSecrets mixes in the (EC)DHE shared secret and derives handshake traffic secrets.
// The transcript must end with ServerHello.
func (s *Schedule) HandshakeSecrets(shared []byte) (client, server []byte, err error) {
	err = s.extract(shared)
	if err != nil {
		return nil, nil, err
	}

	return s.trafficSecrets("c hs traffic", "s hs traffic")
}

// ApplicationSecrets derives application traffic secrets.
// The transcript must end with the server Finished.
func (s *Schedule) ApplicationSecrets() (client, server []byte, err error) {
	err = s.extract(make([]byte, s.Transcript.Size()))
	if err != nil {
		return nil, nil, err
	}

	return s.trafficSecrets("c ap traffic", "s ap traffic")
}

// Finished returns verify_data of the Finished message over the current transcript
// sent by the side owning the handshake traffic secret.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
func (s *Schedule) Finished(secret []byte) ([]byte, error) {
	key, err := expandLabel(s.h, secret, "finished", nil, len(secret))
	if err != nil {
		return nil, err
	}

	m := hmac.New(s.h, key)
	m.Write(s.Transcript.Sum(nil))

	return m.Sum(nil), nil
}

// HelloRetryRequest replaces ClientHello1 in the transcript with its hash.
// It's called after ClientHello1 is written, before HelloRetryRequest.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
func (s *Schedule) HelloRetryRequest() {
	var e Emitter

	sum := s.Transcript.Sum(nil)

	b, st := e.OpenHandshake(nil, MsgMessageHash)
	b = append(b, sum...)
	b = e.CloseHandshake(b, st)

	s.Transcript.Reset()
	s.Transcript.Write(b)
}

// extract moves to the next stage secret.
func (s *Schedule) extract(ikm []byte) (err error) {
	empty := s.h().Sum(nil)

	derived, err := expandLabel(s.h, s.secret, "derived", empty, len(empty))
	if err != nil {
		return err
	}

	s.secret, err = hkdf.Extract(s.h, ikm, derived)

	return err
}

func (s *Schedule) trafficSecrets(clabel, slabel string) (client, server []byte, err error) {
	sum := s.Transcript.Sum(nil)

	client, err = expandLabel(s.h, s.secret, clabel, sum, len(sum))
	if err != nil {
		return nil, nil, err
	}

	server, err = expandLabel(s.h, s.secret, slabel, sum, len(sum))
	if err != nil {
		return nil, nil, err
	}

	return client, server, nil
}
