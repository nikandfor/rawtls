package rawtls

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Captures in testdata are recorded by testdata/capture_chrome.sh and testdata/capture_reality.sh:
// NAME_client.bin and NAME_server.bin are the streams of each side up to the client's first application record,
// NAME_client.keylog is the client's SSLKEYLOGFILE for the connection.
var captures = []string{"gg", "ms", "cf", "re_gg"}

// TestCapture replays captured handshakes with the keylog secrets:
// every record is opened, the transcript is checked by both Finished messages and CertificateVerify.
// The key exchange and the application secrets derivation can't be checked, the client's private key isn't logged.
func TestCapture(t *testing.T) {
	for _, name := range captures {
		t.Run(name, func(t *testing.T) {
			testCapture(t, name)
		})
	}
}

func testCapture(t *testing.T, name string) {
	var d Iterator
	var c ClientSide
	var s ServerSide
	var ch ClientHello
	var sh ServerHello
	var sch Schedule

	client := readTestdata(t, name+"_client.bin")
	server := readTestdata(t, name+"_server.bin")
	secrets := readKeylog(t, name+"_client.keylog")

	chm, _, ci, err := d.HandshakeMessage(nil, client, 0)
	if err != nil {
		t.Fatalf("client hello: %v", err)
	}

	_, err = c.ParseHelloMessage(chm, 0, &ch)
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}

	shm, _, si, err := d.HandshakeMessage(nil, server, 0)
	if err != nil {
		t.Fatalf("server hello: %v", err)
	}

	_, err = s.ParseHelloMessage(shm, 0, &sh)
	if err != nil {
		t.Fatalf("parse server hello: %v", err)
	}
	if sh.IsHelloRetryRequest(shm) {
		t.Fatalf("hello retry request captures are not supported")
	}

	random := hex.EncodeToString(ch.Random.Data(chm))
	if secrets["CLIENT_RANDOM"] != random {
		t.Fatalf("keylog is for %v, client random %v", secrets["CLIENT_RANDOM"], random)
	}

	err = sch.Reset(sh.CipherSuite)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}

	sch.Transcript.Write(chm)
	sch.Transcript.Write(shm)

	shts := unhex(t, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"])
	chts := unhex(t, secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"])

	var leaf *x509.Certificate
	var smsgs, cmsgs []HandshakeType

	sr := captureStream{b: server, i: si}
	sr.resetKeys(t, sh.CipherSuite, shts)

	for {
		tp, m := sr.message(t)
		smsgs = append(smsgs, tp)

		switch tp {
		case MsgEncryptedExtensions:
			var ee EncryptedExtensions

			_, err = s.ParseEncryptedExtensions(m, 0, &ee)
		case MsgCompressedCertificate: // brotli, not in stdlib, CertificateVerify is not checked then
		case MsgCertificate:
			leaf, err = parseLeaf(s, m)
		case MsgCertificateVerify:
			var scheme SignatureScheme
			var sig []byte

			scheme, sig, _, err = d.CertificateVerify(m, 0)
			if err == nil && leaf != nil {
				err = verifySignature(leaf.PublicKey, scheme, AppendSignedContent(nil, true, sch.Transcript.Sum(nil)), sig)
			}
		case MsgFinished:
			var verify []byte

			verify, _, err = d.Finished(m, 0)
			if err == nil {
				err = checkFinished(&sch, shts, verify)
			}
		default:
			t.Fatalf("server message %x", tp)
		}
		if err != nil {
			t.Errorf("server message %x: %v", tp, err)
		}

		sch.Transcript.Write(m)

		if tp == MsgFinished {
			break
		}
	}

	sr.resetKeys(t, sh.CipherSuite, unhex(t, secrets["SERVER_TRAFFIC_SECRET_0"]))
	srecs := sr.records(t)

	cr := captureStream{b: client, i: ci}
	cr.resetKeys(t, sh.CipherSuite, chts)

	for {
		tp, m := cr.message(t)
		cmsgs = append(cmsgs, tp)

		switch tp {
		case MsgEncryptedExtensions: // Chrome sends application_settings (ALPS) here
			_, _, err = d.Message(m, 0, MsgEncryptedExtensions)
		case MsgFinished:
			var verify []byte

			verify, _, err = d.Finished(m, 0)
			if err == nil {
				err = checkFinished(&sch, chts, verify)
			}
		default:
			t.Fatalf("client message %x", tp)
		}
		if err != nil {
			t.Errorf("client message %x: %v", tp, err)
		}

		sch.Transcript.Write(m)

		if tp == MsgFinished {
			break
		}
	}

	cr.resetKeys(t, sh.CipherSuite, unhex(t, secrets["CLIENT_TRAFFIC_SECRET_0"]))
	crecs := cr.records(t)

	t.Logf("suite %04x  group %04x  server %x  client %x  cert %q  application records: server %d, client %d",
		sh.CipherSuite, sh.KeyShare.Group, smsgs, cmsgs, leafName(leaf), srecs, crecs)
}

// captureStream reads a captured stream past the hello: records are opened, change_cipher_spec is skipped.
type captureStream struct {
	b    []byte
	i    int
	keys Keys
	hbuf []byte
}

// message returns the next handshake message.
func (r *captureStream) message(t *testing.T) (HandshakeType, []byte) {
	t.Helper()

	var d Iterator

	for {
		tp, l, st, err := d.HandshakeHeader(r.hbuf, 0)
		if err == nil && st+l <= len(r.hbuf) {
			m := bytes.Clone(r.hbuf[:st+l])

			n := copy(r.hbuf, r.hbuf[st+l:])
			r.hbuf = r.hbuf[:n]

			return tp, m
		}

		data, ctp := r.record(t)
		if ctp != RecHandshake {
			t.Fatalf("record %x at %#x in the middle of the handshake", ctp, r.i)
		}

		r.hbuf = append(r.hbuf, data...)
	}
}

// records opens the rest of the records and returns the number of application data records.
func (r *captureStream) records(t *testing.T) (n int) {
	t.Helper()

	for r.i < len(r.b) {
		_, tp := r.record(t)
		if tp == RecAppData {
			n++
		}
	}

	return n
}

func (r *captureStream) resetKeys(t *testing.T, suite CipherSuite, secret []byte) {
	t.Helper()

	if len(r.hbuf) != 0 {
		t.Fatalf("handshake message spans key change")
	}

	err := r.keys.ResetSecret(suite, secret)
	if err != nil {
		t.Fatalf("reset keys: %v", err)
	}
}

func (r *captureStream) record(t *testing.T) (data []byte, tp ContentType) {
	t.Helper()

	var d Iterator

	for {
		outer, _, l, st, err := d.RecordHeader(r.b, r.i)
		if err != nil || st+l > len(r.b) {
			t.Fatalf("record at %#x: %d/%d %v", r.i, l, len(r.b)-st, err)
		}

		r.i = st + l

		if outer == RecChangeCipherSpec {
			continue
		}
		if outer != RecAppData {
			t.Fatalf("record at %#x: plaintext %x", st-5, outer)
		}

		data, tp, err = r.keys.Open(r.b[:st+l], st)
		if err != nil {
			t.Fatalf("open record at %#x: %v", st-5, err)
		}

		return data, tp
	}
}

func parseLeaf(s ServerSide, m []byte) (*x509.Certificate, error) {
	_, list, _, err := s.Certificate(m, 0)
	if err != nil {
		return nil, err
	}

	cert, _, err := s.CertificateEntry(list, 0)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(bytes.Clone(cert)) // it keeps references to the buffer
}

func checkFinished(sch *Schedule, secret, verify []byte) error {
	want, err := sch.Finished(secret)
	if err != nil {
		return err
	}

	if !bytes.Equal(verify, want) {
		return AlertDecryptError
	}

	return nil
}

func leafName(c *x509.Certificate) string {
	if c == nil {
		return "-"
	}

	return c.Subject.CommonName
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	return data
}

// readKeylog reads NSS key log format lines of a single connection:
// secrets by label, and the client random as CLIENT_RANDOM.
func readKeylog(t *testing.T, name string) map[string]string {
	t.Helper()

	r := make(map[string]string)

	sc := bufio.NewScanner(bytes.NewReader(readTestdata(t, name)))

	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			t.Fatalf("keylog line: %q", sc.Text())
		}

		r[f[0]] = f[2]
		r["CLIENT_RANDOM"] = f[1]
	}

	return r
}
