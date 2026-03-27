package tlsclient

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
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
}

func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := req.Header

	h[http.PHeaderOrderKey] = t.pseudoHeaderOrder

	for key, values := range t.defaultHeaders {
		if existing := h.Get(key); existing != "" {
			continue
		}
		if len(values) > 0 {
			h.Set(key, values[0])
		}
	}

	if h[http.HeaderOrderKey] == nil {
		keys := make([]string, 0, len(h))
		for key := range h {
			keys = append(keys, key)
		}
		rand.Shuffle(len(keys), func(i, j int) {
			keys[i], keys[j] = keys[j], keys[i]
		})
		h[http.HeaderOrderKey] = keys
	}

	return t.base.RoundTrip(req)
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

	return &browserTransport{
		base:              base,
		pseudoHeaderOrder: profile.h2.PseudoHeaderOrder,
		defaultHeaders:    headers,
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
		DialContext: (&net.Dialer{
			Timeout:   c.dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
