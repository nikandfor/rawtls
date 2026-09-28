package rawtls

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// RFC8448: https://datatracker.ietf.org/doc/html/rfc8448#section-3
func TestKeysRFC8448(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secret  string
		key, iv string
		seq     uint64
		tp      ContentType
		payload string
		record  string
	}{{
		name:    "server new session ticket",
		secret:  rfcServerSecret,
		key:     rfcServerKey,
		iv:      rfcServerIV,
		seq:     0,
		tp:      RecHandshake,
		payload: rfcTicket,
		record:  rfcTicketRecord,
	}, {
		name:    "client application data",
		secret:  rfcClientSecret,
		key:     rfcClientKey,
		iv:      rfcClientIV,
		seq:     0,
		tp:      RecAppData,
		payload: rfcAppData,
		record:  rfcClientAppDataRecord,
	}, {
		name:    "server application data",
		secret:  rfcServerSecret,
		key:     rfcServerKey,
		iv:      rfcServerIV,
		seq:     1,
		tp:      RecAppData,
		payload: rfcAppData,
		record:  rfcServerAppDataRecord,
	}, {
		name:    "client alert",
		secret:  rfcClientSecret,
		key:     rfcClientKey,
		iv:      rfcClientIV,
		seq:     1,
		tp:      RecAlert,
		payload: rfcCloseNotify,
		record:  rfcClientCloseNotifyRecord,
	}, {
		name:    "server alert",
		secret:  rfcServerSecret,
		key:     rfcServerKey,
		iv:      rfcServerIV,
		seq:     2,
		tp:      RecAlert,
		payload: rfcCloseNotify,
		record:  rfcServerCloseNotifyRecord,
	}} {
		for _, secret := range [][]byte{nil, unhex(t, tc.secret)} {
			by := "key"
			if secret != nil {
				by = "secret"
			}

			t.Run(tc.name+"/"+by, func(t *testing.T) {
				var e Emitter
				var k Keys

				payload := unhex(t, tc.payload)
				record := unhex(t, tc.record)

				resetKeys(t, &k, TLS_AES_128_GCM_SHA256, unhex(t, tc.key), unhex(t, tc.iv), secret, tc.seq)

				b, st := e.OpenRecord(nil, RecAppData, VerTLS12)
				b = append(b, payload...)
				b = k.Seal(b, st, tc.tp, 0)

				if !bytes.Equal(b, record) {
					t.Errorf("seal: differs at %#x\n got  %x\n want %x", diffAt(b, record), b, record)
				}
				if k.Seq != tc.seq+1 {
					t.Errorf("seal: seq %d, wanted %d", k.Seq, tc.seq+1)
				}

				resetKeys(t, &k, TLS_AES_128_GCM_SHA256, unhex(t, tc.key), unhex(t, tc.iv), secret, tc.seq)

				b = bytes.Clone(record)

				p, tp, err := k.Open(b, 5)
				if err != nil {
					t.Fatalf("open: %v", err)
				}

				if tp != tc.tp || !bytes.Equal(p, payload) {
					t.Errorf("open: type %x, wanted %x\n got  %x\n want %x", tp, tc.tp, p, payload)
				}
				if &p[0] != &b[5] {
					t.Errorf("open: not in place")
				}
				if k.Seq != tc.seq+1 {
					t.Errorf("open: seq %d, wanted %d", k.Seq, tc.seq+1)
				}
			})
		}
	}
}

func TestKeysRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 12)

	for _, suite := range []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256} {
		t.Run(hex.EncodeToString([]byte{byte(suite >> 8), byte(suite)}), func(t *testing.T) {
			var e Emitter
			var w, r Keys

			resetKeys(t, &w, suite, key[:keyLen(suite)], iv, nil, 0)
			resetKeys(t, &r, suite, key[:keyLen(suite)], iv, nil, 0)

			buf := make([]byte, 0, 0x200)

			for i, pad := range []int{0, 1, 100, 0} {
				content := bytes.Repeat([]byte{byte(i + 1)}, 10*i)

				b := append(buf[:0], 0xff, 0xff) // non empty prefix
				b, st := e.OpenRecord(b, RecAppData, VerTLS12)
				b = append(b, content...)
				b = w.Seal(b, st, RecAppData, pad)

				if &b[0] != &buf[:1][0] {
					t.Errorf("record %d: seal reallocated", i)
				}
				if b[0] != 0xff || b[1] != 0xff {
					t.Errorf("record %d: prefix overwritten: %x", i, b[:2])
				}

				p, tp, err := r.Open(b[:], st)
				if err != nil {
					t.Fatalf("record %d: open: %v", i, err)
				}

				if tp != RecAppData || !bytes.Equal(p, content) {
					t.Errorf("record %d: type %x\n got  %x\n want %x", i, tp, p, content)
				}
			}

			if w.Seq != 4 || r.Seq != 4 {
				t.Errorf("seq %d %d, wanted 4", w.Seq, r.Seq)
			}
		})
	}
}

func TestKeysOpenErrors(t *testing.T) {
	var e Emitter
	var w, r Keys

	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 12)

	seal := func(content []byte, tp ContentType) []byte {
		resetKeys(t, &w, TLS_AES_128_GCM_SHA256, key, iv, nil, 0)

		b, st := e.OpenRecord(nil, RecAppData, VerTLS12)
		b = append(b, content...)

		return w.Seal(b, st, tp, 0)
	}

	for _, tc := range []struct {
		name   string
		record []byte
		seq    uint64
		err    error
	}{{
		name:   "tampered",
		record: func() []byte { b := seal([]byte("data"), RecAppData); b[7] ^= 1; return b }(),
		err:    AlertBadRecordMAC,
	}, {
		name:   "wrong seq",
		record: seal([]byte("data"), RecAppData),
		seq:    1,
		err:    AlertBadRecordMAC,
	}, {
		name:   "no content type",
		record: seal([]byte{0, 0}, 0),
		err:    AlertUnexpectedMessage,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			resetKeys(t, &r, TLS_AES_128_GCM_SHA256, key, iv, nil, tc.seq)

			_, _, err := r.Open(tc.record, 5)
			if !errors.Is(err, tc.err) {
				t.Errorf("wanted %v, got %v", tc.err, err)
			}
		})
	}

	err := r.Reset(TLS_AES_128_CCM_SHA256, key, iv)
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("ccm suite: wanted %v, got %v", ErrUnsupported, err)
	}
}

// Vectors are generated by testdata/keyupdate_vectors.py,
// independently of this package: its own HKDF-Expand-Label, AEAD by OpenSSL.
// TLS_AES_128_GCM_SHA256 starts from the RFC8448 client application traffic secret.
// record0 is sealed under secret0 at Seq 3, record1 under the updated secret1 at Seq 0.
func TestKeysUpdate(t *testing.T) {
	content := []byte("key update test")

	for _, tc := range []struct {
		suite   CipherSuite
		secret0 string
		record0 string
		secret1 string
		record1 string
	}{{
		suite:   0x1301,
		secret0: "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
		record0: "17030300202f9ffb22b1eaed1877fdddc8a0e4d971651cfd7bd484a957789dc9" +
			"3494ffc1fc",
		secret1: "fcdfcc72725aaee48bf64e4fd8b749cdbdbab39d90da0b26e2245ca6ea167207",
		record1: "170303002063bec8a6b6f4a036ec09b24ab4f306055996e05364fcacb8eb9c08" +
			"e5fc34c3e0",
	}, {
		suite: 0x1302,
		secret0: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
			"2122232425262728292a2b2c2d2e2f30",
		record0: "170303002016a692924bd3c107e7b230dee867cdbef90329e6a47164e4dc4256" +
			"2a94f5b716",
		secret1: "9e4bc452eeb9e7499109414487d6da7ce8db5b1aa75c7ef63008edb44e0dfbe3" +
			"f7e1d8689e00d4e5859bb784f637fb74",
		record1: "17030300209ffbabb5106d3f78cc0b675c78d08b67d59d0e2ddb70537ff12bce" +
			"a863ab92e3",
	}, {
		suite:   0x1303,
		secret0: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		record0: "1703030020dafd6f116064dcdeeb51d2772828e33dc5974e7a178916275b58ca" +
			"82188505e7",
		secret1: "e8fc7f681aa59e59a6da531ad5b59f2b7ed21605445b04dcbe4727655950a3cf",
		record1: "17030300209e846971a1febe23048db76e8cf0d0d7e9d51f0b322b4f833845ad" +
			"f41e2473bd",
	}} {
		t.Run(hex.EncodeToString([]byte{byte(tc.suite >> 8), byte(tc.suite)}), func(t *testing.T) {
			var e Emitter
			var w, r Keys

			record0 := unhex(t, tc.record0)
			record1 := unhex(t, tc.record1)

			resetKeys(t, &w, tc.suite, nil, nil, unhex(t, tc.secret0), 3)
			resetKeys(t, &r, tc.suite, nil, nil, unhex(t, tc.secret0), 3)

			for i, want := range [][]byte{record0, record1} {
				b, st := e.OpenRecord(nil, RecAppData, VerTLS12)
				b = append(b, content...)
				b = w.Seal(b, st, RecAppData, 0)

				if !bytes.Equal(b, want) {
					t.Errorf("record %d: seal: differs at %#x\n got  %x\n want %x", i, diffAt(b, want), b, want)
				}

				p, tp, err := r.Open(bytes.Clone(want), 5)
				if err != nil {
					t.Fatalf("record %d: open: %v", i, err)
				}

				if tp != RecAppData || !bytes.Equal(p, content) {
					t.Errorf("record %d: open: type %x\n got  %x\n want %x", i, tp, p, content)
				}

				if i != 0 {
					continue
				}

				for _, k := range []*Keys{&w, &r} {
					err = k.Update()
					if err != nil {
						t.Fatalf("update: %v", err)
					}

					if k.Seq != 0 || !bytes.Equal(k.secret, unhex(t, tc.secret1)) {
						t.Errorf("update: seq %d secret %x, wanted 0 %s", k.Seq, k.secret, tc.secret1)
					}
				}
			}
		})
	}
}

func TestKeysUpdateWithoutSecret(t *testing.T) {
	var k Keys

	resetKeys(t, &k, TLS_AES_128_GCM_SHA256, make([]byte, 16), make([]byte, 12), nil, 0)

	defer func() {
		if recover() == nil {
			t.Errorf("wanted panic")
		}
	}()

	_ = k.Update()
}

func resetKeys(t *testing.T, k *Keys, suite CipherSuite, key, iv, secret []byte, seq uint64) {
	t.Helper()

	var err error

	if secret != nil {
		err = k.ResetSecret(suite, secret)
	} else {
		err = k.Reset(suite, key, iv)
	}
	if err != nil {
		t.Fatalf("reset keys: %v", err)
	}

	k.Seq = seq
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	return b
}
