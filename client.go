package tlsclient

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"time"

	"github.com/KakashiHatake324/tls-client/ja3"
	utls "github.com/refraction-networking/utls"
	http "github.com/saucesteals/fhttp"
	"github.com/saucesteals/fhttp/cookiejar"
)

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the overall HTTP client timeout (default: 30s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithProxy sets a proxy URL. Supported schemes: http, https, socks5.
func WithProxy(proxyURL string) Option {
	return func(c *Client) { c.proxyURL = proxyURL }
}

// WithInsecureSkipVerify disables TLS certificate verification.
func WithInsecureSkipVerify() Option {
	return func(c *Client) { c.insecure = true }
}

// WithDialTimeout sets the TCP dial timeout (default: 10s).
func WithDialTimeout(d time.Duration) Option {
	return func(c *Client) { c.dialTimeout = d }
}

// WithH2Profile sets which browser's HTTP/2 fingerprint to use in JA3 mode.
// Accepted values: "chrome", "firefox", "safari". Defaults to "chrome" if unset.
// This controls SETTINGS, WINDOW_UPDATE, pseudo-header order, and priority.
func WithH2Profile(browser string) Option {
	return func(c *Client) { c.h2Browser = browser }
}

// WithOSVersion sets the OS version for mobile platforms (iOS, iPadOS, Android).
// Used in the User-Agent string. For iOS/iPadOS: "18.3", "26.3.0". For Android: "14".
// If not set, defaults to "18.3" for iOS/iPadOS and "14" for Android.
func WithOSVersion(v string) Option {
	return func(c *Client) { c.osVersion = v }
}

// WithCookieJar sets a custom cookie jar. By default a new jar is created
// automatically (like a real browser). Pass nil to disable cookie handling.
func WithCookieJar(jar http.CookieJar) Option {
	return func(c *Client) {
		c.jar = jar
		c.jarSet = true
	}
}

// WithNoCookieJar disables automatic cookie handling.
func WithNoCookieJar() Option {
	return func(c *Client) {
		c.jar = nil
		c.jarSet = true
	}
}

// WithNoRedirects prevents the client from following HTTP redirects.
// The raw 3xx response is returned to the caller.
func WithNoRedirects() Option {
	return func(c *Client) { c.noRedirects = true }
}

// WithMaxRedirects sets the maximum number of redirects to follow (default: 10).
func WithMaxRedirects(n int) Option {
	return func(c *Client) { c.maxRedirects = n }
}

// WithForceTLS12 forces the TLS handshake to negotiate TLS 1.2 instead of 1.3.
// This works around a known uTLS bug (refraction-networking/utls#345) where
// RSA-PSS signature verification fails during TLS 1.3 handshakes with certain
// servers, especially behind proxies. The TLS fingerprint will change slightly
// but cipher suites and extensions are preserved.
func WithForceTLS12() Option {
	return func(c *Client) { c.forceTLS12 = true }
}

// WithPinnedCerts enables SSL pinning using base64-encoded SHA-256 hashes of
// the certificate's Subject Public Key Info (SPKI). If any certificate in the
// peer's chain matches at least one pin, the connection is allowed; otherwise
// the handshake fails. This is the same format used by HPKP and Android
// network security config.
//
// Generate a pin from a PEM certificate:
//
//	openssl x509 -in cert.pem -pubkey -noout |
//	  openssl pkey -pubin -outform DER |
//	  openssl dgst -sha256 -binary |
//	  base64
func WithPinnedCerts(pins ...string) Option {
	return func(c *Client) { c.pins = append(c.pins, pins...) }
}

// ClientInfo holds the browser identity headers generated for the client.
// Use these when setting headers on your requests to stay consistent with
// the TLS/HTTP/2 fingerprint.
type ClientInfo struct {
	UserAgent       string
	SecChUA         string // empty for Firefox/Safari
	SecChUAMobile   string // empty for Firefox/Safari
	SecChUAPlatform string // empty for Firefox/Safari
	Browser         string
	Version         string
	Platform        string
}

// BrowserSpec defines a browser to pick from when using NewClientFromPool.
type BrowserSpec struct {
	Browser  string // "chrome", "firefox", "safari", "edge", "brave"
	Version  string // e.g. "145.0.0.0", "120.0", "18.3"
	Platform string // "mac", "win", "linux", "ios", "ipados"
}

// Client wraps an fhttp.Client with a custom TLS + HTTP/2 fingerprint.
type Client struct {
	httpClient *http.Client
	transport  *http.Transport
	Info       ClientInfo

	timeout      time.Duration
	dialTimeout  time.Duration
	proxyURL     string
	insecure     bool
	forceTLS12   bool
	pins         []string // base64-encoded SHA-256 SPKI hashes for SSL pinning
	h2Browser    string
	osVersion    string
	jar          http.CookieJar
	jarSet       bool // true if user explicitly set jar (even to nil)
	noRedirects  bool
	maxRedirects int
}

// NewClientWithPreset creates a Client that mimics a specific browser version.
//
// Supported browsers and version ranges:
//
//	"chrome"  - Chromium 100+
//	"edge"    - Edge 100+ (Chromium-based)
//	"brave"   - Brave 100+ (Chromium-based)
//	"firefox" - Firefox 55+
//	"safari"  - Safari 16+
//
// Version should be a full version string like "145.0.0.0" or "120.0".
// Platform: "mac", "win", "linux", "ios", "ipados".
func NewClientWithPreset(browser, version, platform string, opts ...Option) (*Client, error) {
	c := &Client{}
	c.applyDefaults()
	for _, o := range opts {
		if o != nil {
			o(c)
		}
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	profile, err := lookupProfile(browser, version, c.osVersion, Platform(platform))
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	transport, base, err := buildPresetTransport(profile, Platform(platform), c)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	headers, err := profile.headerFn(Platform(platform))
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	c.transport = base
	c.httpClient = &http.Client{
		Transport:     transport,
		Timeout:       c.timeout,
		Jar:           c.resolveJar(),
		CheckRedirect: c.redirectPolicy(),
	}
	c.Info = ClientInfo{
		UserAgent:       headers.Get("user-agent"),
		SecChUA:         headers.Get("sec-ch-ua"),
		SecChUAMobile:   headers.Get("sec-ch-ua-mobile"),
		SecChUAPlatform: headers.Get("sec-ch-ua-platform"),
		Browser:         browser,
		Version:         version,
		Platform:        platform,
	}
	return c, nil
}

// NewClientFromPool creates a Client by randomly picking one browser from the
// given pool of BrowserSpecs. Returns the client with Info populated so you
// know which browser was selected.
func NewClientFromPool(pool []BrowserSpec, opts ...Option) (*Client, error) {
	if len(pool) == 0 {
		return nil, fmt.Errorf("tlsclient: empty browser pool")
	}
	pick := pool[rand.IntN(len(pool))]
	return NewClientWithPreset(pick.Browser, pick.Version, pick.Platform, opts...)
}

// NewClientWithJA3 creates a Client whose TLS fingerprint matches the given JA3
// string. HTTP/2 settings default to Chrome's profile unless overridden with
// WithH2Profile("firefox") or WithH2Profile("safari").
func NewClientWithJA3(ja3String string, opts ...Option) (*Client, error) {
	c := &Client{}
	c.applyDefaults()
	for _, o := range opts {
		if o != nil {
			o(c)
		}
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	if _, err := ja3.ToClientHelloSpec(ja3String); err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	h2, err := lookupH2Profile(c.h2Browser)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	transport, base, err := buildJA3Transport(ja3String, h2, c)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	c.transport = base
	c.httpClient = &http.Client{
		Transport:     transport,
		Timeout:       c.timeout,
		Jar:           c.resolveJar(),
		CheckRedirect: c.redirectPolicy(),
	}
	return c, nil
}

// Do executes an HTTP request using the fingerprinted client.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// Get performs a GET request.
func (c *Client) Get(url string) (*http.Response, error) {
	return c.httpClient.Get(url)
}

// Close releases idle connections. Always call when done with the client.
func (c *Client) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// HTTPClient returns the underlying fhttp client for advanced use.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

func (c *Client) applyDefaults() {
	c.timeout = 30 * time.Second
	c.dialTimeout = 10 * time.Second
}

func (c *Client) validate() error {
	if c.proxyURL != "" {
		u, err := url.Parse(c.proxyURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return fmt.Errorf("unsupported proxy scheme %q (use: http, https, socks5)", u.Scheme)
		}
	}
	for i, pin := range c.pins {
		raw, err := base64.StdEncoding.DecodeString(pin)
		if err != nil {
			return fmt.Errorf("invalid pin[%d]: not valid base64: %w", i, err)
		}
		if len(raw) != sha256.Size {
			return fmt.Errorf("invalid pin[%d]: expected %d bytes (SHA-256), got %d", i, sha256.Size, len(raw))
		}
	}
	return nil
}

func (c *Client) redirectPolicy() func(*http.Request, []*http.Request) error {
	if c.noRedirects {
		return func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if c.maxRedirects > 0 {
		max := c.maxRedirects
		return func(_ *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return fmt.Errorf("stopped after %d redirects", max)
			}
			return nil
		}
	}
	return nil
}

func (c *Client) resolveJar() http.CookieJar {
	if c.jarSet {
		return c.jar
	}
	jar, _ := cookiejar.New(nil)
	return jar
}

// Jar returns the cookie jar used by this client. Returns nil if cookies are disabled.
func (c *Client) Jar() http.CookieJar {
	return c.httpClient.Jar
}

func lookupProfile(browser, version, osVersion string, platform Platform) (*browserProfile, error) {
	switch strings.ToLower(strings.TrimSpace(browser)) {
	case "chrome":
		return chromiumProfile("Google Chrome", version, osVersion, platform)
	case "edge":
		return chromiumProfile("Microsoft Edge", version, osVersion, platform)
	case "brave":
		return chromiumProfile("Brave", version, osVersion, platform)
	case "firefox":
		return firefoxProfile(version)
	case "safari":
		return safariProfile(version, platform)
	case "okhttp":
		return okhttpProfile(version)
	default:
		return nil, fmt.Errorf("unsupported browser %q (use: chrome, edge, brave, firefox, safari, okhttp)", browser)
	}
}

func lookupH2Profile(browser string) (*h2Profile, error) {
	switch strings.ToLower(strings.TrimSpace(browser)) {
	case "", "chrome", "edge", "brave":
		return chromiumH2Profile(145), nil
	case "firefox":
		return firefoxH2Profile(), nil
	case "safari":
		return safariMacH2Profile(), nil
	default:
		return nil, fmt.Errorf("unknown h2 profile %q (use: chrome, firefox, safari)", browser)
	}
}

// parseJA3 is a package-level wrapper so transport.go can call the ja3 package
// without a circular import.
func parseJA3(ja3String string) (*utls.ClientHelloSpec, error) {
	return ja3.ToClientHelloSpec(ja3String)
}
