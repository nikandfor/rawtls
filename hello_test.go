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

			var m ClientHello

			i, err := m.Parse(data)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
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

			var m ServerHello

			i, err := m.Parse(data)
			if err != nil {
				t.Errorf("parse: %v", err)
			}
			if i != len(data) {
				t.Errorf("parsed %d/%d", i, len(data))
			}

			if t.Failed() {
				t.Logf("\n%s", m.Dump(data))
				t.Logf("data\n%s", hex.Dump(data))
			}
		})
	}
}
