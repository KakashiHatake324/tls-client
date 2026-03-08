package tlsclient

import (
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
	base.GetTlsClientHelloSpec = func() *utls.ClientHelloSpec {
		spec, _ := utls.UTLSIdToSpec(utls.HelloCustom)
		parsed, err := parseJA3ToSpec(ja3String)
		if err != nil {
			return &spec
		}
		return parsed
	}

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

	if c.proxyURL != "" {
		t.Proxy = func(req *http.Request) (*url.URL, error) {
			return url.Parse(c.proxyURL)
		}
	}

	return t
}
