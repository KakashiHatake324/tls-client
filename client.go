package tlsclient

import (
	"fmt"
	"math/rand/v2"
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

	timeout     time.Duration
	dialTimeout time.Duration
	proxyURL    string
	insecure    bool
	h2Browser   string
	jar         http.CookieJar
	jarSet      bool // true if user explicitly set jar (even to nil)
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
		o(c)
	}

	profile, err := lookupProfile(browser, version)
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
	c.httpClient = &http.Client{Transport: transport, Timeout: c.timeout, Jar: c.resolveJar()}
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
		o(c)
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
	c.httpClient = &http.Client{Transport: transport, Timeout: c.timeout, Jar: c.resolveJar()}
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

func lookupProfile(browser, version string) (*browserProfile, error) {
	switch strings.ToLower(strings.TrimSpace(browser)) {
	case "chrome":
		return chromiumProfile("Google Chrome", version)
	case "edge":
		return chromiumProfile("Microsoft Edge", version)
	case "brave":
		return chromiumProfile("Brave", version)
	case "firefox":
		return firefoxProfile(version)
	case "safari":
		return safariProfile(version)
	default:
		return nil, fmt.Errorf("unsupported browser %q (use: chrome, edge, brave, firefox, safari)", browser)
	}
}

func lookupH2Profile(browser string) (*h2Profile, error) {
	switch strings.ToLower(strings.TrimSpace(browser)) {
	case "", "chrome", "edge", "brave":
		return chromiumH2Profile(145), nil
	case "firefox":
		return firefoxH2Profile(), nil
	case "safari":
		return safariH2Profile(), nil
	default:
		return nil, fmt.Errorf("unknown h2 profile %q (use: chrome, firefox, safari)", browser)
	}
}

// parseJA3 is a package-level wrapper so transport.go can call the ja3 package
// without a circular import.
func parseJA3(ja3String string) (*utls.ClientHelloSpec, error) {
	return ja3.ToClientHelloSpec(ja3String)
}
