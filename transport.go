package tlsclient

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	http "github.com/saucesteals/fhttp"
	http2 "github.com/saucesteals/fhttp/http2"
)

// browserTransport wraps an fhttp transport to inject browser-appropriate
// headers and pseudo-header ordering on every request.
type browserTransport struct {
	base              http.RoundTripper
	pseudoHeaderOrder []string
	defaultHeaders    http.Header
	bypassCache       bool

	// googleHeaders, when set, adds Chrome's Google-only headers to requests
	// bound for a Google property. See google_headers.go.
	googleHeaders *GoogleHeaders
}

func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.bypassCache {
		randomized := randomizeCase(req.URL.Hostname())
		if port := req.URL.Port(); port != "" {
			req.URL.Host = randomized + ":" + port
		} else {
			req.URL.Host = randomized
		}
		req.Host = req.URL.Host
	}

	h := req.Header

	// HTTP/2 wire format uses lowercase header names, and fhttp's HTTP/2
	// write path does case-sensitive map lookups for a handful of headers —
	// most notably "accept-encoding" (http2/transport.go:1636). When our
	// value is stored under the canonical "Accept-Encoding" key fhttp's
	// check misses it and appends its own "accept-encoding: gzip, deflate,
	// br" alongside ours, producing two Accept-Encoding headers on the
	// wire. Force every real header key to lowercase so the map ends up in
	// the shape fhttp expects. Sentinel keys (header order, pseudo-header
	// order) are left alone.
	//
	// This runs FIRST, before any header is read or written below, because
	// http.Header.Get canonicalizes its argument: against a caller-built
	// map literal with lowercase keys (the idiomatic way to control header
	// order) every Get would miss, and the default-header injection below
	// would append a second value under the same lowercased key.
	lowercaseHeaderKeys(h)

	h[http.PHeaderOrderKey] = t.pseudoHeaderOrder

	t.applyGoogleHeaders(req)

	for key, values := range t.defaultHeaders {
		if headerValue(h, key) != "" {
			continue
		}
		if len(values) > 0 {
			h[strings.ToLower(key)] = []string{values[0]}
		}
	}

	lowercaseHeaderKeys(h)

	// fhttp matches order entries against strings.ToLower(headerKey)
	// (header.go headerSorter.Less), so the order list itself must be
	// lowercase or every key falls through to lexicographic order.
	if order, ok := h[http.HeaderOrderKey]; ok {
		h[http.HeaderOrderKey] = lowercaseAll(order)
	} else {
		keys := make([]string, 0, len(h))
		for key := range h {
			if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
				continue
			}
			keys = append(keys, key)
		}
		rand.Shuffle(len(keys), func(i, j int) {
			keys[i], keys[j] = keys[j], keys[i]
		})
		h[http.HeaderOrderKey] = keys
	}

	res, err := t.base.RoundTrip(req)
	if err != nil {
		return res, err
	}
	return decompressResponse(res), nil
}

func lowercaseAll(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToLower(v)
	}
	return out
}

// applyGoogleHeaders adds Chrome's Google-only headers when the request is
// bound for a Google property over HTTPS, matching where real Chrome sends
// them. Headers the caller set explicitly are left alone.
func (t *browserTransport) applyGoogleHeaders(req *http.Request) {
	if t.googleHeaders == nil || req.URL == nil {
		return
	}
	if req.URL.Scheme != "https" || !IsGoogleAssociatedHost(req.URL.Host) {
		return
	}

	// Keys are read and written lowercase: RoundTrip lowercases the whole
	// map before calling this, so Header.Get (which canonicalizes) would
	// miss every entry.
	ua := headerValue(req.Header, "user-agent")
	if ua == "" && t.defaultHeaders != nil {
		ua = t.defaultHeaders.Get("user-agent")
	}

	for key, value := range t.googleHeaders.resolve(ua) {
		if headerValue(req.Header, key) == "" {
			req.Header.Set(key, value)
		}
	}
}

// headerValue reads a header without caring which case the key was stored
// under. RoundTrip lowercases the whole map, but a caller-built map literal
// reaches this package with whatever case it was written in, and
// http.Header.Get only ever looks at the canonical form.
func headerValue(h http.Header, key string) string {
	lower := strings.ToLower(key)
	if v := h[lower]; len(v) > 0 {
		return v[0]
	}
	if v := h[http.CanonicalHeaderKey(key)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// lowercaseHeaderKeys moves every entry in h to a lowercase key, preserving
// values. The header-order and pseudo-header-order sentinel keys are
// skipped. If the same lowercased key appears more than once (e.g. both
// "Accept-Encoding" and "accept-encoding" were set explicitly), values are
// concatenated.
func lowercaseHeaderKeys(h http.Header) {
	for key, values := range h {
		if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
			continue
		}
		lower := strings.ToLower(key)
		if lower == key {
			continue
		}
		if existing, ok := h[lower]; ok {
			h[lower] = append(existing, values...)
		} else {
			h[lower] = values
		}
		delete(h, key)
	}
}

// buildPresetTransport creates a fully configured transport for a browser profile.
func buildPresetTransport(profile *browserProfile, platform Platform, opts *Client) (*browserTransport, *http.Transport, error) {
	specFn, err := profile.specFn(platform)
	if err != nil {
		return nil, nil, err
	}
	if opts.forceTLS12 {
		specFn = capSpecToTLS12(specFn)
	}

	base := buildBaseTransport(opts)
	base.GetTlsClientHelloSpec = specFn

	t2, err := http2.ConfigureTransports(base)
	if err != nil {
		return nil, nil, fmt.Errorf("http2 config: %w", err)
	}

	applyH2Profile(t2, profile.h2)

	headers, err := profile.headerFn(platform)
	if err != nil {
		return nil, nil, err
	}
	if opts.noDefaultHeaders {
		headers = nil
	}

	return &browserTransport{
		base:              base,
		pseudoHeaderOrder: profile.h2.PseudoHeaderOrder,
		defaultHeaders:    headers,
		bypassCache:       opts.bypassCache,
		googleHeaders:     opts.googleHeaders,
	}, base, nil
}

// buildJA3Transport creates a transport for a JA3 string with the given HTTP/2 profile.
func buildJA3Transport(ja3String string, h2 *h2Profile, opts *Client) (*browserTransport, *http.Transport, error) {
	base := buildBaseTransport(opts)
	specFn := func() *utls.ClientHelloSpec {
		spec, _ := utls.UTLSIdToSpec(utls.HelloCustom)
		parsed, err := parseJA3ToSpec(ja3String)
		if err != nil {
			return &spec
		}
		return parsed
	}
	if opts.forceTLS12 {
		specFn = capSpecToTLS12(specFn)
	}
	base.GetTlsClientHelloSpec = specFn

	t2, err := http2.ConfigureTransports(base)
	if err != nil {
		return nil, nil, fmt.Errorf("http2 config: %w", err)
	}

	applyH2Profile(t2, h2)

	return &browserTransport{
		base:              base,
		pseudoHeaderOrder: h2.PseudoHeaderOrder,
		bypassCache:       opts.bypassCache,
	}, base, nil
}

func parseJA3ToSpec(ja3String string) (*utls.ClientHelloSpec, error) {
	// lazy import to avoid circular dependency
	return parseJA3(ja3String)
}

func applyH2Profile(t2 *http2.Transport, p *h2Profile) {
	t2.Settings = p.Settings
	t2.MaxHeaderListSize = p.MaxHeaderListSize
	t2.InitialWindowSize = p.InitialWindowSize
	t2.HeaderTableSize = p.HeaderTableSize

	if p.ConnectionFlow > 0 {
		t2.TransportConnFlow = p.ConnectionFlow
	}
	if p.HeaderPriority != nil {
		t2.HeaderPriority = p.HeaderPriority
	}
}

func buildBaseTransport(c *Client) *http.Transport {
	t := &http.Transport{
		DialContext:           c.resolveDialContext(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   c.dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if c.insecure || len(c.pins) > 0 {
		cfg := &utls.Config{InsecureSkipVerify: c.insecure}
		if len(c.pins) > 0 {
			cfg.VerifyPeerCertificate = buildPinVerifier(c.pins)
		}
		t.TLSClientConfig = cfg
	}

	if c.proxyURL != "" {
		proxyURL := c.proxyURL
		t.Proxy = func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
	}

	return t
}

// resolveDialContext builds the dial function for the transport, layering the
// IPv4-only narrowing on top of whatever dialer the caller supplied.
func (c *Client) resolveDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := c.dialContext
	if dial == nil {
		dial = (&net.Dialer{
			Timeout:   c.dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}
	if !c.disableIPv6 {
		return dial
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dial(ctx, ipv4Only(network), addr)
	}
}

func ipv4Only(network string) string {
	switch network {
	case "tcp", "tcp6":
		return "tcp4"
	case "udp", "udp6":
		return "udp4"
	}
	return network
}

// capSpecToTLS12 wraps a spec function to force TLS 1.2 by removing TLS 1.3
// from the SupportedVersions extension and stripping TLS 1.3-only cipher suites.
// This works around utls#345 where RSA-PSS verification fails in TLS 1.3.
func capSpecToTLS12(original func() *utls.ClientHelloSpec) func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		spec := original()
		spec.TLSVersMax = utls.VersionTLS12

		// Remove TLS 1.3 from SupportedVersions extension.
		for _, ext := range spec.Extensions {
			if sv, ok := ext.(*utls.SupportedVersionsExtension); ok {
				filtered := sv.Versions[:0]
				for _, v := range sv.Versions {
					if v != utls.VersionTLS13 {
						filtered = append(filtered, v)
					}
				}
				sv.Versions = filtered
				break
			}
		}

		// Remove TLS 1.3-only cipher suites (0x13xx).
		filtered := spec.CipherSuites[:0]
		for _, cs := range spec.CipherSuites {
			if cs>>8 != 0x13 {
				filtered = append(filtered, cs)
			}
		}
		spec.CipherSuites = filtered

		return spec
	}
}

// buildPinVerifier returns a VerifyPeerCertificate callback that checks whether
// any certificate in the chain has a SPKI SHA-256 hash matching one of the pins.
func buildPinVerifier(pins []string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	pinSet := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		pinSet[p] = struct{}{}
	}

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				continue
			}
			hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			encoded := base64.StdEncoding.EncodeToString(hash[:])
			if _, ok := pinSet[encoded]; ok {
				return nil
			}
		}
		return fmt.Errorf("tlsclient: ssl pinning failed: none of the %d certificate(s) matched any pinned public key", len(rawCerts))
	}
}

// randomizeCase returns s with each letter randomly upper- or lower-cased.
func randomizeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			if rand.IntN(2) == 0 {
				r -= 'a' - 'A'
			}
		} else if r >= 'A' && r <= 'Z' {
			if rand.IntN(2) == 0 {
				r += 'a' - 'A'
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}
