package rawtls

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzClientHello(f *testing.F) {
	seed(f, "client")

	f.Fuzz(func(t *testing.T, data []byte) {
		var c ClientSide
		var m ClientHello

		i, err := c.ParseHello(data, &m)

		_ = m.Dump(data) // must not panic on any parse result

		if err != nil {
			return
		}

		b := c.AppendHello(nil, &m, data)
		if d := diffAt(b, data[:i]); d >= 0 {
			t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
		}
	})
}

func FuzzServerHello(f *testing.F) {
	seed(f, "server")

	f.Fuzz(func(t *testing.T, data []byte) {
		var s ServerSide
		var m ServerHello

		i, err := s.ParseHello(data, &m)

		_ = m.Dump(data)

		if err != nil {
			return
		}

		b := s.AppendHello(nil, &m, data)
		if d := diffAt(b, data[:i]); d >= 0 {
			t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
		}
	})
}

func seed(f *testing.F, side string) {
	files, err := filepath.Glob(filepath.Join("testdata", "*_"+side+".bin"))
	if err != nil {
		f.Fatalf("glob: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatalf("read %v: %v", file, err)
		}

		f.Add(firstRecord(data))
	}
}

// FuzzHandshakeMessage checks reassembled messages are complete and parsers don't panic on them.
func FuzzHandshakeMessage(f *testing.F) {
	for _, name := range captures {
		data, err := os.ReadFile(filepath.Join("testdata", name+"_client.bin"))
		if err != nil {
			f.Fatalf("read %v: %v", name, err)
		}

		data = firstRecord(data)

		f.Add(fragment(RecHandshake, VerTLS10, data[5:], 100))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var d Iterator
		var c ClientSide
		var s ServerSide
		var ch ClientHello
		var sh ServerHello

		msg, _, i, err := d.HandshakeMessage([]byte{0xdd}, data, 0)
		if err != nil {
			if i != 0 || len(msg) != 1 {
				t.Errorf("error: %d %d %v", i, len(msg), err)
			}

			return
		}

		_, l, st, err := d.HandshakeHeader(msg, 1)
		if err != nil || st+l != len(msg) || i > len(data) {
			t.Errorf("message: %d+%d/%d  records %d/%d %v", st, l, len(msg), i, len(data), err)
		}

		_, _ = c.ParseHelloMessage(msg, 1, &ch)
		_, _ = s.ParseHelloMessage(msg, 1, &sh)

		_ = ch.Dump(msg)
		_ = sh.Dump(msg)
	})
}

// FuzzHandshakeMessages checks message parsers never panic.
func FuzzHandshakeMessages(f *testing.F) {
	f.Add([]byte{byte(MsgCertificate), 0, 0, 0})
	f.Add([]byte{byte(MsgEncryptedExtensions), 0, 0, 2, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		var c ClientSide
		var s ServerSide
		var ch ClientHello
		var sh ServerHello
		var ee EncryptedExtensions

		_, _ = c.ParseHelloMessage(data, 0, &ch)
		_, _ = s.ParseHelloMessage(data, 0, &sh)
		_, _ = s.ParseEncryptedExtensions(data, 0, &ee)
		_, _, _, _ = s.CertificateVerify(data, 0)
		_, _, _ = s.Finished(data, 0)

		_, list, _, err := s.Certificate(data, 0)
		for i := 0; err == nil && i < len(list); {
			_, i, err = s.CertificateEntry(list, i)
		}

		_ = ch.Dump(data)
		_ = sh.Dump(data)
	})
}
