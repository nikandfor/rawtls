package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls "nikand.dev/go/rawtls"
)

var (
	listen = flag.String("listen", ":6443", "Address to listen to")
	target = flag.String("target", "www.microsoft.com:443", "Address to route connection to")
	dump   = flag.Bool("dump", false, "print handshake message as hexdump")
	save   = flag.String("save", "", "file name pattern to save the first connection streams to, XXX is replaced with client or server")
)

var (
	dialer net.Dialer
	saving atomic.Bool
)

func main() {
	flag.Parse()

	cmd := flag.Arg(0)
	if cmd == "" {
		cmd = "server"
	}

	var err error
	if cmd == "server" {
		err = serve()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v: %v\n", cmd, err)
		os.Exit(1)
	}
}

func serve() error {
	ctx := context.Background()

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	defer closer(l, &err, "close listener")

	go func() {
		<-ctx.Done()

		d, ok := l.(interface{ SetDeadline(time.Time) error })
		if !ok {
			return
		}

		_ = d.SetDeadline(time.Unix(1, 0))
	}()

	log.Printf("listening %v", l.Addr())

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		c, err := l.Accept()
		if isTimeout(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("accept tcp: %w", err)
		}

		wg.Go(func() {
			err := handleConn(ctx, c, *target)
			if err != nil {
				log.Printf("connection: %v", err)
			}
		})
	}
}

func handleConn(ctx context.Context, c net.Conn, target string) (err error) {
	defer closer(c, &err, "close client conn")

	r, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	defer closer(r, &err, "close target conn")

	first := make([]byte, 0x4000)

	n, err := c.Read(first) // some connections are closed empty
	if errors.Is(err, io.EOF) && n == 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read client: %w", err)
	}

	first = first[:n]

	_, err = r.Write(first)
	if err != nil {
		return fmt.Errorf("write target: %w", err)
	}

	rec := *save != "" && saving.CompareAndSwap(false, true) // only the first connection is saved

	var stop atomic.Bool
	var serr error
	var wg sync.WaitGroup

	wg.Go(func() {
		serr = relay(c, r, nil, "server", rec, &stop)
		closeWrite(c)
	})

	err = relay(r, c, first, "client", rec, &stop)
	closeWrite(r)

	wg.Wait()

	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("server: %w", serr)
	}

	return nil
}

// relay copies src to dst.
// If rec is set, it records the stream, starting with b, until the client sends its first application data
// after Finished: by then the server flight is complete and the first application records are in.
func relay(dst, src net.Conn, b []byte, side string, rec bool, stop *atomic.Bool) (err error) {
	buf := make([]byte, 0x4000)

	for {
		n, err := src.Read(buf)

		if rec && stop.Load() {
			rec = false

			serr := saveStream(side, b)
			if serr != nil {
				return serr
			}
		}

		if rec {
			b = append(b, buf[:n]...)
		}

		if rec && side == "client" && flightEnd(b) >= 0 {
			b = b[:flightEnd(b)]
			rec = false
			stop.Store(true)

			serr := saveStream(side, b)
			if serr != nil {
				return serr
			}
		}

		if n != 0 {
			_, werr := dst.Write(buf[:n])
			if werr != nil {
				return fmt.Errorf("write: %w", werr)
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}

	if rec {
		return saveStream(side, b)
	}

	return nil
}

// flightEnd returns the end of the second application data record, which is the one after Finished.
// It's -1 if it's not in b yet.
func flightEnd(b []byte) int {
	var d tls.Iterator

	appdata := 0

	for i := 0; ; {
		tp, _, l, st, err := d.RecordHeader(b, i)
		if err != nil || st+l > len(b) {
			return -1
		}

		i = st + l

		if tp != tls.RecAppData {
			continue
		}

		appdata++

		if appdata == 2 {
			return i
		}
	}
}

// recordsEnd returns the end of the last complete record.
func recordsEnd(b []byte) int {
	var d tls.Iterator

	i := 0

	for {
		_, _, l, st, err := d.RecordHeader(b, i)
		if err != nil || st+l > len(b) {
			return i
		}

		i = st + l
	}
}

func saveStream(side string, b []byte) error {
	b = b[:recordsEnd(b)]

	logHello(side, b)

	name := strings.Replace(*save, "XXX", side, 1)

	err := os.WriteFile(name, b, 0o644)
	if err != nil {
		return fmt.Errorf("save %v stream: %w", side, err)
	}

	log.Printf("%v stream saved: %v  %d bytes", side, name, len(b))

	return nil
}

func logHello(side string, b []byte) {
	var d tls.Iterator

	msg, ver, i, err := d.HandshakeMessage(nil, b, 0)
	if err != nil {
		log.Printf("%v hello: %v", side, err)
		return
	}

	if *dump {
		log.Printf("%v hello  %4x\n%s", side, i, hex.Dump(b[:i]))
	}

	if side == "client" {
		var m tls.ClientHello

		m.RecordLegacyVersion = ver

		_, err = tls.ClientSide{}.ParseHelloMessage(msg, 0, &m)
		log.Printf("client hello  err %v\n%s", err, m.Dump(msg))

		return
	}

	var m tls.ServerHello

	m.RecordLegacyVersion = ver

	_, err = tls.ServerSide{}.ParseHelloMessage(msg, 0, &m)
	log.Printf("server hello  err %v\n%s", err, m.Dump(msg))
}

func closeWrite(c net.Conn) {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		return
	}

	_ = cw.CloseWrite() // the peer may be gone already, the relay error is reported instead
}

func closer(c io.Closer, errp *error, msg string) {
	e := c.Close()
	if *errp == nil && e != nil {
		*errp = fmt.Errorf("%s: %w", msg, e)
	}
}

func isTimeout(err error) bool {
	to, ok := err.(interface{ Timeout() bool })

	return ok && to.Timeout()
}
