// h2dump terminates a TLS connection (self-signed, ALPN h2 or http/1.1) and
// prints the client's HTTP/2 fingerprint: SETTINGS id:val in frame order, the
// connection WINDOW_UPDATE increment, per-stream priority, and the request
// header name order. Point a browser or the tls-client at
// https://localhost:8444 and read the ground truth off the wire.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/saucesteals/fhttp/http2"
	"github.com/saucesteals/fhttp/http2/hpack"
)

func selfCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "h2dump"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serve(ln net.Listener, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tconn.Handshake(); err != nil {
		log.Println("handshake:", err)
		return
	}
	fmt.Printf("negotiated ALPN: %q\n", tconn.ConnectionState().NegotiatedProtocol)
	if tconn.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	// Consume the HTTP/2 client connection preface before framing.
	buf := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(tconn, buf); err != nil {
		log.Println("preface:", err)
		return
	}
	f := http2.NewFramer(tconn, tconn)
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	sawSettings := false
	for n := 0; n < 24; n++ {
		frame, err := f.ReadFrame()
		if err != nil {
			fmt.Println("read end:", err)
			break
		}
		switch fv := frame.(type) {
		case *http2.MetaHeadersFrame:
			pr := fv.Priority
			fmt.Printf("HEADERS stream=%d exclusive=%v dep=%d weight=%d\n", fv.StreamID, pr.Exclusive, pr.StreamDep, pr.Weight)
			for _, hf := range fv.Fields {
				fmt.Printf("  H: %s: %.60s\n", hf.Name, hf.Value)
			}
			// minimal 200 response so the client can finish
			tconn.Write([]byte{})
		case *http2.HeadersFrame:
			fmt.Printf("HEADERS(raw) stream=%d exclusive=%v dep=%d weight=%d\n", fv.StreamID, fv.Priority.Exclusive, fv.Priority.StreamDep, fv.Priority.Weight)
		case *http2.SettingsFrame:
			var ids []string
			fv.ForeachSetting(func(s http2.Setting) error {
				ids = append(ids, fmt.Sprintf("%d:%d", s.ID, s.Val))
				return nil
			})
			fmt.Printf("SETTINGS order=[%v] ack=%v\n", ids, fv.IsAck())
			sawSettings = true
		case *http2.WindowUpdateFrame:
			fmt.Printf("WINDOW_UPDATE stream=%d incr=%d\n", fv.StreamID, fv.Increment)
		case *http2.DataFrame:
			fmt.Printf("DATA stream=%d len=%d\n", fv.StreamID, len(fv.Data()))
		case *http2.PriorityFrame:
			fmt.Printf("PRIORITY stream=%d exclusive=%v dep=%d weight=%d\n", fv.StreamID, fv.Exclusive, fv.StreamDep, fv.Weight)
		default:
			fmt.Printf("FRAME %T\n", frame)
		}
		if _, isHeaders := frame.(*http2.MetaHeadersFrame); isHeaders {
			// give the client a moment for trailing frames, then stop
			time.Sleep(400 * time.Millisecond)
		}
	}
	_ = sawSettings
	tconn.Close()
}

func main() {
	port := flag.String("addr", "127.0.0.1:8444", "listen address")
	n := flag.Int("n", 1, "number of connections to dump")
	flag.Parse()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfCert()},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	for i := 0; i < *n; i++ {
		ln, err := tls.Listen("tcp", *port, cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("=== listening on", *port, "===")
		done := make(chan struct{})
		go serve(ln, done)
		<-done
		ln.Close()
	}
}
