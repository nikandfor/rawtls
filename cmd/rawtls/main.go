package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	tls "nikand.dev/go/rawtls"
)

var (
	listen = flag.String("listen", ":6443", "Address to listen to")
	target = flag.String("target", "www.microsoft.com:443", "Address to route connection to")
	dump   = flag.Bool("dump", false, "print handshake message as hexdump")
	save   = flag.String("save", "", "file name pattern to save")
)

var dialer net.Dialer

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

	buf := make([]byte, 0x1000)

	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("read from client: %w", err)
	}

	var cl tls.ClientHello

	i, err := tls.Client{}.ParseHello(buf[:n], &cl)
	if true {
		log.Printf("\n%s", cl.Dump(buf[:n]))
	}

	if *dump {
		log.Printf("client hello  %4x/%4x  err %v\n%s", i, n, err, hex.Dump(buf[:i]))
	}
	if q := *save; err == nil && q != "" {
		name := strings.Replace(q, "XXX", "client", 1)

		err := os.WriteFile(name, buf[:i], 0o644)
		if err != nil {
			log.Printf("write client dump: %v", err)
		}
	}

	_, err = r.Write(buf[:n])
	if err != nil {
		return fmt.Errorf("write to target: %w", err)
	}

	n, err = r.Read(buf)
	if err != nil {
		return fmt.Errorf("read from target: %w", err)
	}

	var srv tls.ServerHello

	i, err = tls.Server{}.ParseHello(buf[:n], &srv)
	if true {
		log.Printf("\n%s", srv.Dump(buf[:n]))
	}

	if *dump {
		log.Printf("server hello  %4x/%4x  err %v\n%s", i, n, err, hex.Dump(buf[:i]))
	}
	if q := *save; err == nil && q != "" {
		name := strings.Replace(q, "XXX", "server", 1)

		err := os.WriteFile(name, buf[:i], 0o644)
		if err != nil {
			log.Printf("write server dump: %v", err)
		}
	}

	_, err = c.Write(buf[:n])
	if err != nil {
		return fmt.Errorf("write to client: %w", err)
	}

	return nil
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
