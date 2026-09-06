package rawtls

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClientHello(t *testing.T) {
	for _, name := range []string{"ms", "gg", "cf", "re_gg"} {
		file := name + "_client_hello.bin"

		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", file))
			if errors.Is(err, os.ErrNotExist) {
				t.Skip("no test file")
			}
			if err != nil {
				t.Errorf("read client hello file: %v", err)
				return
			}

			var c Client
			var m ClientHello

			i, err := c.ParseHello(data, &m)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
			}

			b := c.AppendHello(nil, &m, data)
			if d := diffAt(b, data[:i]); d >= 0 {
				t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
			}

			b = c.AppendHello(append(b[:0], 0xff, 0xff), &m, data) // reused buffer, non empty prefix
			if d := diffAt(b[2:], data[:i]); d >= 0 {
				t.Errorf("append to prefix: differs at %#x, encoded %#x, wanted %#x", d, len(b)-2, i)
			}

			// t.Logf("hello %+v\n", m)
			if t.Failed() {
				t.Logf("\n%s", m.Dump(data))
				t.Logf("data\n%s", hex.Dump(data))
			}
		})
	}
}

func TestServerHello(t *testing.T) {
	for _, name := range []string{"ms", "gg", "cf", "re_gg"} {
		file := name + "_server_hello.bin"

		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", file))
			if errors.Is(err, os.ErrNotExist) {
				t.Skip("no test file")
			}
			if err != nil {
				t.Errorf("read client hello file: %v", err)
				return
			}

			var s Server
			var m ServerHello

			i, err := s.ParseHello(data, &m)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
			}

			b := s.AppendHello(nil, &m, data)
			if d := diffAt(b, data[:i]); d >= 0 {
				t.Errorf("append: differs at %#x, encoded %#x, wanted %#x", d, len(b), i)
			}

			b = s.AppendHello(append(b[:0], 0xff, 0xff), &m, data) // reused buffer, non empty prefix
			if d := diffAt(b[2:], data[:i]); d >= 0 {
				t.Errorf("append to prefix: differs at %#x, encoded %#x, wanted %#x", d, len(b)-2, i)
			}

			if t.Failed() {
				t.Logf("\n%s", m.Dump(data))
				t.Logf("data\n%s", hex.Dump(data))
			}
		})
	}
}

func diffAt(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}

	if len(a) != len(b) {
		return min(len(a), len(b))
	}

	return -1
}
