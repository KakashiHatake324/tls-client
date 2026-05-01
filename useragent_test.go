package tlsclient

import "testing"

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
