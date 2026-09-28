package rawtls

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
)

type (
	// KeyShare is the private part of the client key share.
	KeyShare struct {
		Group KeyGroup

		ecdh  *ecdh.PrivateKey
		mlkem *mlkem.DecapsulationKey768
	}
)

// defaultGroups are the supported groups in preference order.
var defaultGroups = []KeyGroup{GroupX25519MLKEM768, GroupX25519, GroupSecp256r1}

// Generate generates the client key share for the group.
// It returns the public key to send in key_share.
//
// X25519MLKEM768 key is ML-KEM-768 encapsulation key followed by X25519 key.
//
//	draft-ietf-tls-ecdhe-mlkem: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
func (k *KeyShare) Generate(group KeyGroup) (pub []byte, err error) {
	k.Group = group
	k.mlkem = nil

	if group == GroupX25519MLKEM768 {
		k.mlkem, err = mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}

		pub = k.mlkem.EncapsulationKey().Bytes()
	}

	curve, ok := groupCurve(group)
	if !ok {
		return nil, fmt.Errorf("%w: group %04x", ErrUnsupported, group)
	}

	k.ecdh, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return append(pub, k.ecdh.PublicKey().Bytes()...), nil
}

// SharedSecret computes the shared secret from the server key share.
// Invalid server key share is reported as illegal_parameter.
func (k *KeyShare) SharedSecret(peer []byte) (shared []byte, err error) {
	if k.mlkem != nil {
		if len(peer) != mlkem.CiphertextSize768+32 {
			return nil, AlertIllegalParameter
		}

		shared, err = k.mlkem.Decapsulate(peer[:mlkem.CiphertextSize768])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
		}

		peer = peer[mlkem.CiphertextSize768:]
	}

	pub, err := k.ecdh.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
	}

	s, err := k.ecdh.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
	}

	return append(shared, s...), nil
}

// ServerKeyShare computes the server key share and the shared secret from the client key share.
// Invalid client key share is reported as illegal_parameter.
func ServerKeyShare(group KeyGroup, peer []byte) (pub, shared []byte, err error) {
	if group == GroupX25519MLKEM768 {
		if len(peer) != mlkem.EncapsulationKeySize768+32 {
			return nil, nil, AlertIllegalParameter
		}

		ek, err := mlkem.NewEncapsulationKey768(peer[:mlkem.EncapsulationKeySize768])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
		}

		shared, pub = ek.Encapsulate()
		peer = peer[mlkem.EncapsulationKeySize768:]
	}

	curve, ok := groupCurve(group)
	if !ok {
		return nil, nil, fmt.Errorf("%w: group %04x", ErrUnsupported, group)
	}

	peerKey, err := curve.NewPublicKey(peer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
	}

	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	s, err := key.ECDH(peerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", AlertIllegalParameter, err)
	}

	return append(pub, key.PublicKey().Bytes()...), append(shared, s...), nil
}

func groupCurve(g KeyGroup) (ecdh.Curve, bool) {
	switch g {
	case GroupX25519, GroupX25519MLKEM768:
		return ecdh.X25519(), true
	case GroupSecp256r1:
		return ecdh.P256(), true
	}

	return nil, false
}
