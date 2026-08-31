package tlsclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	http "github.com/saucesteals/fhttp"
)

var errDialStub = errors.New("dial stub")

const payload = "the quick brown fox jumps over the lazy dog, repeatedly, at length"

func responseWith(encoding string, body []byte) *http.Response {
	h := http.Header{}
	if encoding != "" {
		h.Set("Content-Encoding", encoding)
	}
	h.Set("Content-Length", "999")
	return &http.Response{
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: 999,
	}
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(got)
}

func TestDecompressResponseDecodesEveryEncoding(t *testing.T) {
	cases := []struct {
		encoding string
		compress func(io.Writer) io.WriteCloser
	}{
		{"gzip", func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) }},
		{"br", func(w io.Writer) io.WriteCloser { return brotli.NewWriter(w) }},
		{"deflate", func(w io.Writer) io.WriteCloser { return zlib.NewWriter(w) }},
		{"zstd", func(w io.Writer) io.WriteCloser {
			z, _ := zstd.NewWriter(w)
			return z
		}},
	}

	for _, tc := range cases {
		t.Run(tc.encoding, func(t *testing.T) {
			var buf bytes.Buffer
			w := tc.compress(&buf)
			if _, err := io.WriteString(w, payload); err != nil {
				t.Fatalf("compress: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("close compressor: %v", err)
			}

			res := decompressResponse(responseWith(tc.encoding, buf.Bytes()))

			if got := readAll(t, res); got != payload {
				t.Errorf("body = %q, want %q", got, payload)
			}
			if ce := res.Header.Get("Content-Encoding"); ce != "" {
				t.Errorf("Content-Encoding survived decoding: %q", ce)
			}
			if !res.Uncompressed {
				t.Error("Uncompressed not set")
			}
			if res.ContentLength != -1 {
				t.Errorf("ContentLength = %d, want -1", res.ContentLength)
			}
		})
	}
}

// TestDecompressResponseHandlesRawDeflate covers servers that send a bare
// DEFLATE stream under Content-Encoding: deflate instead of the zlib wrapper
// the spec calls for.
func TestDecompressResponseHandlesRawDeflate(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	io.WriteString(w, payload)
	w.Close()

	res := decompressResponse(responseWith("deflate", buf.Bytes()))
	if got := readAll(t, res); got != payload {
		t.Errorf("body = %q, want %q", got, payload)
	}
}

// TestDecompressResponseSkipsAlreadyDecoded is the regression guard for
// double-decoding: fhttp decodes gzip/br/deflate itself on HTTP/2 and leaves
// Content-Encoding in place, so the header alone must not drive the decision.
func TestDecompressResponseSkipsAlreadyDecoded(t *testing.T) {
	res := responseWith("br", []byte(payload))
	res.Uncompressed = true

	res = decompressResponse(res)

	if got := readAll(t, res); got != payload {
		t.Errorf("body was decoded a second time: %q", got)
	}
	if ce := res.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("stale Content-Encoding left on an already-decoded body: %q", ce)
	}
}

func TestDecompressResponseLeavesUnknownAndEmptyBodies(t *testing.T) {
	res := decompressResponse(responseWith("", []byte(payload)))
	if got := readAll(t, res); got != payload {
		t.Errorf("identity body = %q, want %q", got, payload)
	}
	if res.Header.Get("Content-Length") == "" {
		t.Error("Content-Length was stripped from an untouched response")
	}

	// An empty gzip body must not fail until it is actually read, and even
	// then only with the compressor's own error — never a panic.
	empty := decompressResponse(responseWith("gzip", nil))
	if _, err := io.ReadAll(empty.Body); err == nil {
		t.Log("empty gzip body read cleanly")
	}
	empty.Body.Close()
}

// TestRoundTripLowercasesBeforeReadingHeaders guards the invariant the whole
// header path depends on: a caller-built lowercase map literal must be seen by
// the default-header injection, or the profile value lands under the canonical
// key and lowercaseHeaderKeys merges the two into a duplicate header.
func TestRoundTripLowercasesBeforeReadingHeaders(t *testing.T) {
	var captured http.Header
	tr := &browserTransport{
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			captured = r.Header
			return &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		pseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		defaultHeaders:    http.Header{"User-Agent": {"profile-ua"}, "Sec-Ch-Ua": {"profile-hint"}},
	}

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header = http.Header{"user-agent": {"caller-ua"}}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if got := captured["user-agent"]; len(got) != 1 || got[0] != "caller-ua" {
		t.Errorf("user-agent = %v, want exactly [caller-ua]", got)
	}
	if _, ok := captured["User-Agent"]; ok {
		t.Error("canonical User-Agent key survived; it will duplicate on the wire")
	}
	if got := captured["sec-ch-ua"]; len(got) != 1 || got[0] != "profile-hint" {
		t.Errorf("sec-ch-ua = %v, want the profile default under a lowercase key", got)
	}
}

// TestRoundTripLowercasesHeaderOrder covers fhttp's order matching, which
// lowercases the map key but not the order entry (header.go headerSorter.Less),
// so a canonical order list silently degrades to lexicographic order.
func TestRoundTripLowercasesHeaderOrder(t *testing.T) {
	var captured http.Header
	tr := &browserTransport{
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			captured = r.Header
			return &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header = http.Header{
		"user-agent":         {"ua"},
		"accept":             {"*/*"},
		http.HeaderOrderKey:  {"User-Agent", "Accept"},
		http.PHeaderOrderKey: {":method"},
	}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	want := []string{"user-agent", "accept"}
	got := captured[http.HeaderOrderKey]
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// TestFoldRedirectHeaders covers the duplicate-referer trap: fhttp sets a
// canonical "Referer" on every redirect hop without checking for the lowercase
// key the rest of this package uses.
func TestFoldRedirectHeaders(t *testing.T) {
	h := http.Header{
		"referer":           {"https://origin.example/first"},
		"user-agent":        {"ua"},
		http.HeaderOrderKey: {"referer", "user-agent"},
	}
	h.Set("Referer", "https://origin.example/second")

	foldRedirectHeaders(h)

	if got := h["referer"]; len(got) != 1 || got[0] != "https://origin.example/second" {
		t.Errorf("referer = %v, want exactly the redirect's value", got)
	}
	if _, ok := h["Referer"]; ok {
		t.Error("canonical Referer survived; it will duplicate on the wire")
	}
	if got := h[http.HeaderOrderKey]; len(got) != 2 {
		t.Errorf("header order sentinel was mangled: %v", got)
	}
}

func TestWithoutDefaultHeadersLeavesRequestUntouched(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithoutDefaultHeaders())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	tr, ok := c.httpClient.Transport.(*browserTransport)
	if !ok {
		t.Fatalf("transport is %T, want *browserTransport", c.httpClient.Transport)
	}
	if tr.defaultHeaders != nil {
		t.Errorf("default headers still installed: %v", tr.defaultHeaders)
	}
	if c.Info.UserAgent == "" {
		t.Error("Info.UserAgent was cleared; the identity should still be available")
	}
}

func TestDisableIPV6NarrowsTheDialNetwork(t *testing.T) {
	var networks []string
	c := &Client{
		dialTimeout: 0,
		disableIPv6: true,
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			networks = append(networks, network)
			return nil, errDialStub
		},
	}

	for _, in := range []string{"tcp", "tcp6", "tcp4", "udp"} {
		c.resolveDialContext()(context.Background(), in, "example.com:443")
	}

	want := []string{"tcp4", "tcp4", "tcp4", "udp4"}
	for i, w := range want {
		if networks[i] != w {
			t.Errorf("network[%d] = %q, want %q", i, networks[i], w)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
