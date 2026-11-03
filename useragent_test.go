package tlsclient

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseUserAgent(t *testing.T) {
	cases := []struct {
		name    string
		ua      string
		browser string
		version string
		plat    Platform
		osVer   string
	}{
		{
			name:    "chrome mac",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
			browser: "chrome",
			version: "145.0.0.0",
			plat:    PlatformMac,
		},
		{
			name:    "chrome windows",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.165 Safari/537.36",
			browser: "chrome",
			version: "146.0.7680.165",
			plat:    PlatformWindows,
		},
		{
			name:    "chrome linux",
			ua:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
			browser: "chrome",
			version: "140.0.0.0",
			plat:    PlatformLinux,
		},
		{
			name:    "chrome android",
			ua:      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
			browser: "chrome",
			version: "145.0.0.0",
			plat:    PlatformAndroid,
			osVer:   "14",
		},
		{
			name:    "chrome ios (CriOS)",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.0.0 Mobile/15E148 Safari/604.1",
			browser: "chrome",
			version: "145.0.0.0",
			plat:    PlatformIOS,
			osVer:   "18.3",
		},
		{
			name:    "chrome ipados (CriOS)",
			ua:      "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/132.0.0.0 Mobile/15E148 Safari/604.1",
			browser: "chrome",
			version: "132.0.0.0",
			plat:    PlatformIPadOS,
			osVer:   "17.5",
		},
		{
			name:    "edge windows",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
			browser: "edge",
			version: "145.0.0.0",
			plat:    PlatformWindows,
		},
		{
			name:    "firefox mac",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
			browser: "firefox",
			version: "134.0",
			plat:    PlatformMac,
		},
		{
			name:    "firefox android",
			ua:      "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
			browser: "firefox",
			version: "120.0",
			plat:    PlatformAndroid,
			osVer:   "14",
		},
		{
			name:    "safari mac",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
			browser: "safari",
			version: "18.3",
			plat:    PlatformMac,
		},
		{
			name:    "safari ios",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
			browser: "safari",
			version: "18.3",
			plat:    PlatformIOS,
			osVer:   "18.3",
		},
		{
			name:    "safari ipados",
			ua:      "Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
			browser: "safari",
			version: "18.3",
			plat:    PlatformIPadOS,
			osVer:   "18.3",
		},
		{
			name:    "okhttp",
			ua:      "okhttp/4.10.0",
			browser: "okhttp",
			version: "4.10.0",
			plat:    PlatformAndroid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseUserAgent(tc.ua)
			if err != nil {
				t.Fatalf("ParseUserAgent error: %v", err)
			}
			if got.Browser != tc.browser {
				t.Errorf("browser = %q, want %q", got.Browser, tc.browser)
			}
			if got.Version != tc.version {
				t.Errorf("version = %q, want %q", got.Version, tc.version)
			}
			if got.Platform != tc.plat {
				t.Errorf("platform = %q, want %q", got.Platform, tc.plat)
			}
			if got.OSVersion != tc.osVer {
				t.Errorf("os_version = %q, want %q", got.OSVersion, tc.osVer)
			}
		})
	}
}

func TestParseUserAgentErrors(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"NotABrowser/1.0",
	}
	for _, ua := range cases {
		if _, err := ParseUserAgent(ua); err == nil {
			t.Errorf("expected error for %q, got nil", ua)
		}
	}
}

func TestNewClientWithUserAgent(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
	c, err := NewClientWithUserAgent(ua)
	if err != nil {
		t.Fatalf("NewClientWithUserAgent: %v", err)
	}
	defer c.Close()

	if c.Info.Browser != "chrome" {
		t.Errorf("browser = %q, want chrome", c.Info.Browser)
	}
	if c.Info.Version != "145.0.0.0" {
		t.Errorf("version = %q, want 145.0.0.0", c.Info.Version)
	}
	if c.Info.Platform != "mac" {
		t.Errorf("platform = %q, want mac", c.Info.Platform)
	}
	if c.Info.UserAgent != ua {
		t.Errorf("UserAgent = %q, want exact input", c.Info.UserAgent)
	}
	if c.Info.SecChUA == "" {
		t.Error("SecChUA should be populated for Chrome")
	}
}

func TestNewClientWithUserAgentIOSChrome(t *testing.T) {
	ua := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.0.0 Mobile/15E148 Safari/604.1"
	c, err := NewClientWithUserAgent(ua)
	if err != nil {
		t.Fatalf("NewClientWithUserAgent: %v", err)
	}
	defer c.Close()

	if c.Info.Browser != "chrome" {
		t.Errorf("browser = %q, want chrome", c.Info.Browser)
	}
	if c.Info.Platform != "ios" {
		t.Errorf("platform = %q, want ios", c.Info.Platform)
	}
	if c.Info.UserAgent != ua {
		t.Errorf("UserAgent should round-trip exactly, got %q", c.Info.UserAgent)
	}
}

// TestParseUserAgentFallbacks covers the shapes that real traffic throws at
// the parser but a hand-written UA never does: in-app WebViews, Chromium
// re-skins, crawlers with no platform token, and builds too old for any
// preset to model.
func TestParseUserAgentFallbacks(t *testing.T) {
	cases := []struct {
		name    string
		ua      string
		browser string
		version string
		plat    Platform
		osVer   string
	}{
		{
			name:    "google app webview iphone",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/436.4.969249353 Mobile/15E148 Safari/604.1",
			browser: "safari",
			version: "26.6.1",
			plat:    PlatformIOS,
			osVer:   "26.6.1",
		},
		{
			name:    "google app webview ipad",
			ua:      "Mozilla/5.0 (iPad; CPU OS 26_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/436.4.969249353 Mobile/15E148 Safari/604.1",
			browser: "safari",
			version: "26.6.1",
			plat:    PlatformIPadOS,
			osVer:   "26.6.1",
		},
		{
			name:    "facebook in-app browser",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/24A437 Safari/604.1 [FBAN/FBIOS;FBAV/580.0.0.47.72;FBSV/27.0;IABMV/1]",
			browser: "safari",
			version: "27.0",
			plat:    PlatformIOS,
			osVer:   "27.0",
		},
		{
			name:    "instagram in-app browser",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/23G71 Instagram 452.0.1.39.54 (iPhone17,1; iOS 26_6; sk_SK; sk; scale=3.00; 1206x2622; IABMV/1; 1093431980) NW/3 Safari/604.1",
			browser: "safari",
			version: "26.6",
			plat:    PlatformIOS,
			osVer:   "26.6",
		},
		{
			// Apple requires every iOS browser to render with WebKit over the
			// system TLS stack, so Firefox for iOS handshakes as Safari.
			name:    "firefox for ios",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/154.0 Mobile/15E148 Safari/604.1",
			browser: "safari",
			version: "18.7",
			plat:    PlatformIOS,
			osVer:   "18.7",
		},
		{
			name:    "googlebot has no platform token",
			ua:      "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/151.0.7922.108 Safari/537.36",
			browser: "chrome",
			version: "151.0.7922.108",
			plat:    PlatformLinux,
		},
		{
			// Edge/12.246 is EdgeHTML, not Chromium; the Chrome token wins.
			name:    "legacy edgehtml token",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36 Edge/12.246",
			browser: "chrome",
			version: "125.0.6422.60",
			plat:    PlatformWindows,
		},
		{
			name:    "edge android",
			ua:      "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36 EdgA/151.0.0.0",
			browser: "edge",
			version: "151.0.0.0",
			plat:    PlatformAndroid,
			osVer:   "10",
		},
		{
			name:    "samsung internet is chromium",
			ua:      "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/30.0 Chrome/143.0.0.0 Mobile Safari/537.36",
			browser: "chrome",
			version: "143.0.0.0",
			plat:    PlatformAndroid,
			osVer:   "10",
		},
		{
			name:    "chromeos reports as linux",
			ua:      "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
			browser: "chrome",
			version: "151.0.0.0",
			plat:    PlatformLinux,
		},
		{
			// Android WebView puts Version/4.0 ahead of the Chrome token; that
			// must not be mistaken for Safari's Version/.
			name:    "android webview",
			ua:      "Mozilla/5.0 (Linux; Android 16; PJF110 Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/152.0.7977.88 Mobile Safari/537.36 TwitterAndroid/12.25.0-prod.01",
			browser: "chrome",
			version: "152.0.7977.88",
			plat:    PlatformAndroid,
			osVer:   "16",
		},
		{
			// Chrome 59 predates nothing we model, but it is below no floor
			// either, so it maps to the oldest matching era preset.
			name:    "long-eol chrome",
			ua:      "Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36",
			browser: "chrome",
			version: "59.0.3071.125",
			plat:    PlatformAndroid,
			osVer:   "7.0",
		},
		{
			// Safari 10 is below safariMinVersion and gets raised to the floor
			// rather than rejected.
			name:    "safari below the floor is clamped",
			ua:      "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1",
			browser: "safari",
			version: "11.0",
			plat:    PlatformIOS,
			osVer:   "10.3.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseUserAgent(tc.ua)
			if err != nil {
				t.Fatalf("ParseUserAgent error: %v", err)
			}
			if got.Browser != tc.browser {
				t.Errorf("browser = %q, want %q", got.Browser, tc.browser)
			}
			if got.Version != tc.version {
				t.Errorf("version = %q, want %q", got.Version, tc.version)
			}
			if got.Platform != tc.plat {
				t.Errorf("platform = %q, want %q", got.Platform, tc.plat)
			}
			if got.OSVersion != tc.osVer {
				t.Errorf("os_version = %q, want %q", got.OSVersion, tc.osVer)
			}
		})
	}
}

func loadUserAgentCorpus(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/useragents.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var uas []string
	if err := json.Unmarshal(b, &uas); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(uas) == 0 {
		t.Fatal("corpus is empty")
	}
	return uas
}

// TestUserAgentCorpus runs every User-Agent in testdata/useragents.json, a
// sample of real traffic, through NewClientWithUserAgent. Every one must yield
// a client that sends that exact UA back out.
func TestUserAgentCorpus(t *testing.T) {
	for _, ua := range loadUserAgentCorpus(t) {
		c, err := NewClientWithUserAgent(ua)
		if err != nil {
			t.Errorf("NewClientWithUserAgent(%q): %v", ua, err)
			continue
		}
		if got := transportUserAgent(t, c); got != ua {
			t.Errorf("outgoing user-agent = %q, want %q", got, ua)
		}
		c.Close()
	}
}

// transportUserAgent reports the user-agent the client would put on a request
// that does not carry one of its own.
func transportUserAgent(t *testing.T, c *Client) string {
	t.Helper()
	tr, ok := c.httpClient.Transport.(*browserTransport)
	if !ok {
		t.Fatalf("transport is %T, want *browserTransport", c.httpClient.Transport)
	}
	return headerValue(tr.defaultHeaders, "user-agent")
}

// The preset's synthesized UA differs from most real ones: it hardcodes a
// device model and a Windows version. The caller's string has to win.
func TestNewClientWithUserAgentOverridesPresetHeader(t *testing.T) {
	cases := []string{
		"Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/23G71 Instagram 452.0.1.39.54 (iPhone17,1; iOS 26_6; sk_SK; sk; scale=3.00; 1206x2622; IABMV/1; 1093431980) NW/3 Safari/604.1",
	}

	for _, ua := range cases {
		c, err := NewClientWithUserAgent(ua)
		if err != nil {
			t.Fatalf("NewClientWithUserAgent(%q): %v", ua, err)
		}
		if got := transportUserAgent(t, c); got != ua {
			t.Errorf("outgoing user-agent = %q, want %q", got, ua)
		}
		if c.GetDefaultUserAgent() != ua {
			t.Errorf("GetDefaultUserAgent = %q, want %q", c.GetDefaultUserAgent(), ua)
		}
		c.Close()
	}
}

// A corpus spot-check over the wire: every sampled UA must complete a TLS 1.3
// handshake, negotiate h2, and arrive at the server unmodified.
func TestUserAgentCorpusLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	uas := loadUserAgentCorpus(t)
	const samples = 24
	step := len(uas) / samples
	if step < 1 {
		step = 1
	}

	for i := 0; i < len(uas); i += step {
		ua := uas[i]
		c, err := NewClientWithUserAgent(ua)
		if err != nil {
			t.Errorf("NewClientWithUserAgent(%q): %v", ua, err)
			continue
		}

		pr := fetchPeet(t, c)
		if pr.UserAgent != ua {
			t.Errorf("server saw user-agent %q, want %q", pr.UserAgent, ua)
		}
		if pr.TLS.TLSVersionNegotiated != "772" {
			t.Errorf("%q: negotiated TLS %s, want 772", ua, pr.TLS.TLSVersionNegotiated)
		}
		if pr.HTTPVersion != "h2" {
			t.Errorf("%q: http version %s, want h2", ua, pr.HTTPVersion)
		}
		if !strings.HasPrefix(pr.TLS.JA4, "t13d") {
			t.Errorf("%q: JA4 %s, want a t13d prefix", ua, pr.TLS.JA4)
		}
		c.Close()
	}
}
