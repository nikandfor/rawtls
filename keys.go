package rawtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
)

type (
	// Keys protect records of one direction of a connection.
	Keys struct {
		Suite CipherSuite

		// Seq is the number of records already processed under the keys.
		// It's a part of the nonce and it's never sent,
		// so a wrong Seq fails every record the same way a wrong key does.
		Seq uint64

		aead   cipher.AEAD
		iv     [12]byte
		secret []byte
	}
)

// Record size limits.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const (
	MaxPlaintext  = 1 << 14
	MaxCiphertext = MaxPlaintext + 256
)

// ResetSecret derives the traffic key and iv from the traffic secret,
// sets them, and resets Seq. Keys set this way can be updated.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
func (k *Keys) ResetSecret(suite CipherSuite, secret []byte) error {
	h := suiteHash(suite)
	if h == nil {
		return fmt.Errorf("%w: cipher suite %04x", ErrUnsupported, suite)
	}

	if len(secret) != h().Size() {
		panic(len(secret))
	}

	key, err := expandLabel(h, secret, "key", nil, keyLen(suite))
	if err != nil {
		return err
	}

	iv, err := expandLabel(h, secret, "iv", nil, len(k.iv))
	if err != nil {
		return err
	}

	err = k.Reset(suite, key, iv)
	if err != nil {
		return err
	}

	k.secret = append(k.secret[:0], secret...)

	return nil
}

// Update moves to the next traffic secret as KeyUpdate requires and resets Seq.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
func (k *Keys) Update() error {
	if len(k.secret) == 0 {
		panic("update keys without secret: use ResetSecret")
	}

	secret, err := expandLabel(suiteHash(k.Suite), k.secret, "traffic upd", nil, len(k.secret))
	if err != nil {
		return err
	}

	return k.ResetSecret(k.Suite, secret)
}

// Reset sets the traffic keys and resets Seq.
// Keys set this way can't be updated.
func (k *Keys) Reset(suite CipherSuite, key, iv []byte) error {
	l := keyLen(suite)
	if l == 0 {
		return fmt.Errorf("%w: cipher suite %04x", ErrUnsupported, suite)
	}

	if len(key) != l {
		panic(len(key))
	}
	if len(iv) != len(k.iv) {
		panic(len(iv))
	}

	var aead cipher.AEAD
	var err error

	switch suite {
	case TLS_CHACHA20_POLY1305_SHA256:
		aead, err = chacha20poly1305.New(key)
	default:
		var b cipher.Block

		b, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(b)
		}
	}
	if err != nil {
		return err
	}

	k.Suite = suite
	k.Seq = 0
	k.aead = aead
	k.secret = k.secret[:0]
	copy(k.iv[:], iv)

	return nil
}

// Seal protects the record in place.
//
// The record is started with Emitter.OpenRecord:
// b[st-5:st] is its header, b[st:] is the content.
// Inner content type tp and pad zero bytes are appended to the content,
// the header length is set, and the authentication tag is appended.
//
//	b, st := e.OpenRecord(b, RecAppData, VerTLS12)
//	b = append(b, data...)
//	b = k.Seal(b, st, RecAppData, 0)
func (k *Keys) Seal(b []byte, st int, tp ContentType, pad int) []byte {
	b = appendU8(b, tp)
	b = appendZeros(b, pad)

	if l := len(b) - st; l > MaxPlaintext+1 {
		panic(l)
	}

	var e Emitter

	e.SetLen16(b, st, len(b)-st+k.aead.Overhead())

	b = slices.Grow(b, k.aead.Overhead())

	nonce := k.nonce()

	c := k.aead.Seal(b[st:st], nonce[:], b[st:], b[st-5:st])

	k.Seq++

	return b[:st+len(c)]
}

// Open deprotects the record in place.
//
// b[st-5:st] is the record header, b[st:] is exactly the protected payload.
// It returns the content with inner content type and padding stripped.
// The payload is overwritten even if Open fails.
func (k *Keys) Open(b []byte, st int) (_ []byte, tp ContentType, err error) {
	if l := len(b) - st; l < 0 || l > MaxCiphertext {
		return nil, 0, AlertRecordOverflow
	}

	nonce := k.nonce()

	p, err := k.aead.Open(b[st:st], nonce[:], b[st:], b[st-5:st])
	if err != nil {
		return nil, 0, AlertBadRecordMAC
	}

	k.Seq++

	if len(p) > MaxPlaintext+1 {
		return nil, 0, AlertRecordOverflow
	}

	i := len(p) - 1
	for i >= 0 && p[i] == 0 {
		i--
	}

	if i < 0 {
		return nil, 0, AlertUnexpectedMessage
	}

	return p[:i], ContentType(p[i]), nil
}

func (k *Keys) nonce() (n [12]byte) {
	n = k.iv
	s := k.Seq

	for i := len(n) - 1; i >= len(n)-8; i-- {
		n[i] ^= byte(s)
		s >>= 8
	}

	return n
}

// expandLabel is HKDF-Expand-Label.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
func expandLabel(h func() hash.Hash, secret []byte, label string, context []byte, l int) ([]byte, error) {
	var e Emitter
	var buf [64]byte

	b := appendU16(buf[:0], l)

	b, st := e.OpenLen8(b)
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = e.CloseLen8(b, st)

	b, st = e.OpenLen8(b)
	b = append(b, context...)
	b = e.CloseLen8(b, st)

	return hkdf.Expand(h, secret, string(b), l)
}

func suiteHash(s CipherSuite) func() hash.Hash {
	switch s {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		return sha256.New
	case TLS_AES_256_GCM_SHA384:
		return sha512.New384
	}

	return nil
}

func keyLen(s CipherSuite) int {
	switch s {
	case TLS_AES_128_GCM_SHA256:
		return 16
	case TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
		return 32
	}

	return 0
}
