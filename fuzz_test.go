package rawtls

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzClientHello(f *testing.F) {
	seed(f, "client")

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Client
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
		var s Server
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
	files, err := filepath.Glob(filepath.Join("testdata", "*_"+side+"_hello.bin"))
	if err != nil {
		f.Fatalf("glob: %v", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			f.Fatalf("read %v: %v", file, err)
		}

		f.Add(data)
	}
}
