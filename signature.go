package rawtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
)

// defaultSignatureSchemes are the schemes the client accepts in preference order.
// PKCS#1 v1.5 is listed for certificate signatures only, CertificateVerify can't use it.
var defaultSignatureSchemes = []SignatureScheme{
	SigECDSASecp256r1SHA256, SigRSAPSSRSAeSHA256, SigEd25519,
	SigECDSASecp384r1SHA384, SigRSAPSSRSAeSHA384,
	SigECDSASecp521r1SHA512, SigRSAPSSRSAeSHA512,
	SigRSAPKCS1SHA256, SigRSAPKCS1SHA384, SigRSAPKCS1SHA512,
}

// AppendSignedContent appends the content signed in CertificateVerify over the transcript hash.
//
//	RFC8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
func AppendSignedContent(b []byte, server bool, transcript []byte) []byte {
	for range 64 {
		b = append(b, ' ')
	}

	if server {
		b = append(b, "TLS 1.3, server CertificateVerify"...)
	} else {
		b = append(b, "TLS 1.3, client CertificateVerify"...)
	}

	b = append(b, 0)

	return append(b, transcript...)
}

// verifySignature verifies CertificateVerify signature.
// Failed signature is reported as decrypt_error, unfit scheme as illegal_parameter.
func verifySignature(pub crypto.PublicKey, scheme SignatureScheme, content, sig []byte) error {
	if !slices.Contains(keySchemes(pub), scheme) {
		return fmt.Errorf("%w: signature scheme %04x doesn't fit the certificate key", AlertIllegalParameter, scheme)
	}

	var ok bool

	switch pub := pub.(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(pub, content, sig)
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(pub, digest(scheme, content), sig)
	case *rsa.PublicKey:
		err := rsa.VerifyPSS(pub, schemeHash(scheme), digest(scheme, content), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		ok = err == nil
	}

	if !ok {
		return fmt.Errorf("%w: bad certificate verify signature", AlertDecryptError)
	}

	return nil
}

// signatureScheme picks the scheme for the key the peer accepts.
// peer is the signature_algorithms list.
func signatureScheme(pub crypto.PublicKey, peer []byte) (SignatureScheme, bool) {
	for _, s := range keySchemes(pub) {
		if hasU16(peer, s) {
			return s, true
		}
	}

	return 0, false
}

// sign signs CertificateVerify content.
func sign(key crypto.Signer, scheme SignatureScheme, content []byte) ([]byte, error) {
	if scheme == SigEd25519 {
		return key.Sign(rand.Reader, content, crypto.Hash(0))
	}

	h := schemeHash(scheme)

	var opts crypto.SignerOpts = h

	if _, ok := key.Public().(*rsa.PublicKey); ok {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}

	return key.Sign(rand.Reader, digest(scheme, content), opts)
}

// keySchemes returns CertificateVerify schemes usable with the key.
func keySchemes(pub crypto.PublicKey) []SignatureScheme {
	switch pub := pub.(type) {
	case ed25519.PublicKey:
		return []SignatureScheme{SigEd25519}
	case *rsa.PublicKey:
		return []SignatureScheme{SigRSAPSSRSAeSHA256, SigRSAPSSRSAeSHA384, SigRSAPSSRSAeSHA512}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return []SignatureScheme{SigECDSASecp256r1SHA256}
		case elliptic.P384():
			return []SignatureScheme{SigECDSASecp384r1SHA384}
		case elliptic.P521():
			return []SignatureScheme{SigECDSASecp521r1SHA512}
		}
	}

	return nil
}

func schemeHash(s SignatureScheme) crypto.Hash {
	switch s {
	case SigECDSASecp256r1SHA256, SigRSAPSSRSAeSHA256:
		return crypto.SHA256
	case SigECDSASecp384r1SHA384, SigRSAPSSRSAeSHA384:
		return crypto.SHA384
	case SigECDSASecp521r1SHA512, SigRSAPSSRSAeSHA512:
		return crypto.SHA512
	}

	panic(s)
}

func digest(s SignatureScheme, content []byte) []byte {
	h := schemeHash(s).New()
	h.Write(content)

	return h.Sum(nil)
}

// hasU16 reports whether the list of 16-bit values contains v.
func hasU16[T ints16](list []byte, v T) bool {
	for i := 0; i+2 <= len(list); {
		if u16[T](list, &i) == v {
			return true
		}
	}

	return false
}
