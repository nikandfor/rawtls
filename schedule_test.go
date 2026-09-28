package rawtls

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

func TestScheduleRFC8448(t *testing.T) {
	var s Schedule

	priv, err := ecdh.X25519().NewPrivateKey(unhex(t, rfcClientPriv))
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	pub, err := ecdh.X25519().NewPublicKey(unhex(t, rfcServerPub))
	if err != nil {
		t.Fatalf("server key: %v", err)
	}

	shared, err := priv.ECDH(pub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}

	check := func(name string, got []byte, want string) {
		t.Helper()

		if !bytes.Equal(got, unhex(t, want)) {
			t.Errorf("%v\n got  %x\n want %s", name, got, want)
		}
	}

	check("shared", shared, rfcShared)

	err = s.Reset(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}

	check("early secret", s.secret, rfcEarlySecret)

	s.Transcript.Write(unhex(t, rfcClientHello))
	s.Transcript.Write(unhex(t, rfcServerHello))

	chs, shs, err := s.HandshakeSecrets(shared)
	if err != nil {
		t.Fatalf("handshake secrets: %v", err)
	}

	check("handshake secret", s.secret, rfcHandshakeSecret)
	check("client handshake secret", chs, rfcClientHandshakeSecret)
	check("server handshake secret", shs, rfcServerHandshakeSecret)

	s.Transcript.Write(unhex(t, rfcEncryptedExtensions))
	s.Transcript.Write(unhex(t, rfcCertificate))
	s.Transcript.Write(unhex(t, rfcCertificateVerify))

	fin, err := s.Finished(shs)
	if err != nil {
		t.Fatalf("server finished: %v", err)
	}

	check("server finished", fin, rfcServerFinishedVerify)

	s.Transcript.Write(unhex(t, rfcServerFinished))

	cas, sas, err := s.ApplicationSecrets()
	if err != nil {
		t.Fatalf("application secrets: %v", err)
	}

	check("master secret", s.secret, rfcMasterSecret)
	check("client application secret", cas, rfcClientSecret)
	check("server application secret", sas, rfcServerSecret)

	fin, err = s.Finished(chs)
	if err != nil {
		t.Fatalf("client finished: %v", err)
	}

	check("client finished", fin, rfcClientFinishedVerify)
}

func TestScheduleHelloRetryRequestRFC8448(t *testing.T) {
	var s Schedule

	priv, err := ecdh.P256().NewPrivateKey(unhex(t, rfcHRRClientPriv))
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	pub, err := ecdh.P256().NewPublicKey(unhex(t, rfcHRRServerPub))
	if err != nil {
		t.Fatalf("server key: %v", err)
	}

	shared, err := priv.ECDH(pub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}

	if !bytes.Equal(shared, unhex(t, rfcHRRShared)) {
		t.Errorf("shared\n got  %x\n want %s", shared, rfcHRRShared)
	}

	err = s.Reset(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}

	s.Transcript.Write(unhex(t, rfcHRRClientHello1))
	s.HelloRetryRequest()
	s.Transcript.Write(unhex(t, rfcHRRHelloRetryRequest))
	s.Transcript.Write(unhex(t, rfcHRRClientHello2))
	s.Transcript.Write(unhex(t, rfcHRRServerHello))

	chs, shs, err := s.HandshakeSecrets(shared)
	if err != nil {
		t.Fatalf("handshake secrets: %v", err)
	}

	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{name: "handshake secret", got: s.secret, want: rfcHRRHandshakeSecret},
		{name: "client handshake secret", got: chs, want: rfcHRRClientHandshakeSecret},
		{name: "server handshake secret", got: shs, want: rfcHRRServerHandshakeSecret},
	} {
		if !bytes.Equal(c.got, unhex(t, c.want)) {
			t.Errorf("%v\n got  %x\n want %s", c.name, c.got, c.want)
		}
	}
}
