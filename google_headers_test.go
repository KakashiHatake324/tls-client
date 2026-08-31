package tlsclient

import (
	"strings"
	"testing"

	http "github.com/saucesteals/fhttp"
)

// TestClientDataHeaderMatchesCapture pins the x-client-data encoder against
// values a real Chrome 151 sent to www.google.com. Two fresh profiles produced
// two different single-ID values, which is what makes them useful test vectors:
// each decodes to one variation_id in protobuf field 1.
func TestClientDataHeaderMatchesCapture(t *testing.T) {
	cases := []struct {
		name       string
		variations []int32
		triggers   []int32
		want       string
	}{
		{"captured profile A", []int32{3328974}, nil, "CM6XywE="},
		{"captured profile B", []int32{3323505}, nil, "CPHsygE="},
		{"empty", nil, nil, ""},
		// 0x08 tag, varint 1; then 0x18 tag (field 3), varint 2.
		{"both fields", []int32{1}, []int32{2}, "CAEYAg=="},
		{"sorted and deduped", []int32{3, 1, 3, 2}, nil, "CAEIAggD"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClientDataHeader(tc.variations, tc.triggers); got != tc.want {
				t.Errorf("ClientDataHeader(%v, %v) = %q, want %q",
					tc.variations, tc.triggers, got, tc.want)
			}
		})
	}
}

// TestBrowserValidationIsDeterministic covers the documented construction. The
// value is NOT verified against real Chrome — see BrowserValidation for why —
// so this only pins the algorithm the library implements.
func TestBrowserValidationIsDeterministic(t *testing.T) {
	const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"

	first := BrowserValidation(ChromeAPIKey(PlatformMac), ua)
	if first != BrowserValidation(ChromeAPIKey(PlatformMac), ua) {
		t.Error("BrowserValidation is not deterministic")
	}
	// base64 of a 20-byte SHA-1 digest.
	if len(first) != 28 || !strings.HasSuffix(first, "=") {
		t.Errorf("value = %q, want 28 chars of base64-encoded SHA-1", first)
	}
	if same := BrowserValidation(ChromeAPIKey(PlatformWindows), ua); same == first {
		t.Error("different platform keys produced the same value")
	}
	if same := BrowserValidation(ChromeAPIKey(PlatformMac), ua+"x"); same == first {
		t.Error("different user agents produced the same value")
	}
}

func TestIsGoogleAssociatedHost(t *testing.T) {
	google := []string{
		// Observed receiving the headers in the Chrome 151 capture.
		"www.google.com", "www.gstatic.com", "fonts.gstatic.com",
		"play.google.com", "ogads-pa.clients6.google.com",
		"content-autofill.googleapis.com",
		// Country domains and the rest of Chromium's associated-domain set.
		"google.com", "google.co.uk", "www.google.com.au", "www.youtube.com",
		"youtu.be", "googleads.g.doubleclick.net", "www.googleadservices.com",
		"pagead2.googlesyndication.com", "lh3.googleusercontent.com",
		"WWW.GOOGLE.COM", "www.google.com:443", "www.google.com.",
	}
	for _, h := range google {
		if !IsGoogleAssociatedHost(h) {
			t.Errorf("IsGoogleAssociatedHost(%q) = false, want true", h)
		}
	}

	notGoogle := []string{
		"", "example.com", "tls.peet.ws", "google.evil.com", "notgoogle.com",
		"google.com.evil.net", "mygoogle.com", "youtube.evil.org", "localhost",
	}
	for _, h := range notGoogle {
		if IsGoogleAssociatedHost(h) {
			t.Errorf("IsGoogleAssociatedHost(%q) = true, want false", h)
		}
	}
}

// TestGoogleHeadersResolve pins the header set against the Chrome 151 capture,
// including the exact copyright wording, which is "All Rights Reserved."
func TestGoogleHeadersResolve(t *testing.T) {
	got := GoogleHeaders{
		ClientData: "CM6XywE=",
		Validation: "S7hKo5PWMhrUgzQMwm5wWB2agsI=",
		Year:       "2026",
	}.resolve("ua")

	want := map[string]string{
		"x-browser-channel":    "stable",
		"x-browser-year":       "2026",
		"x-browser-validation": "S7hKo5PWMhrUgzQMwm5wWB2agsI=",
		"x-browser-copyright":  "Copyright 2026 Google LLC. All Rights Reserved.",
		"x-client-data":        "CM6XywE=",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d headers, want %d: %v", len(got), len(want), got)
	}
}

// TestGoogleHeadersOmitsUnknownValues checks the safe default: with nothing
// supplied, the two value-bearing headers are left off rather than guessed.
func TestGoogleHeadersOmitsUnknownValues(t *testing.T) {
	got := GoogleHeaders{Year: "2026"}.resolve("ua")

	for _, key := range []string{"x-browser-validation", "x-client-data"} {
		if _, ok := got[key]; ok {
			t.Errorf("%s was sent with no value configured: %q", key, got[key])
		}
	}
	if got["x-browser-channel"] != "stable" {
		t.Errorf("channel = %q, want stable", got["x-browser-channel"])
	}
}

// TestGoogleHeadersValidationSecret covers deriving the value from a secret.
func TestGoogleHeadersValidationSecret(t *testing.T) {
	const ua = "Mozilla/5.0 test"
	const secret = "seed" + "AIzaSyExample"
	got := GoogleHeaders{ValidationSecret: secret, Year: "2026"}.resolve(ua)

	want := BrowserValidation(secret, ua)
	if got["x-browser-validation"] != want {
		t.Errorf("x-browser-validation = %q, want %q", got["x-browser-validation"], want)
	}

	// An explicit value wins over the secret.
	got = GoogleHeaders{ValidationSecret: secret, Validation: "explicit"}.resolve(ua)
	if got["x-browser-validation"] != "explicit" {
		t.Errorf("explicit Validation was overridden: %q", got["x-browser-validation"])
	}
}

// TestBrowserValidationEmptySeedMatchesLegacy pins the empty-seed case: with the
// seed "" this is the old base64(sha1(api_key + ua)) formula that reproduced
// Chrome ~134-143. The value is a regression anchor, not a current-Chrome value.
func TestBrowserValidationEmptySeedMatchesLegacy(t *testing.T) {
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

	// Empty seed + mac key, computed independently.
	if got, want := BrowserValidation(ChromeAPIKey(PlatformMac), ua), "gaDqXtWJKNMORzYkmKfW9PCuEPo="; got != want {
		t.Errorf("empty-seed mac = %q, want %q", got, want)
	}
	// The real Chrome 151 value, which the empty-seed formula must NOT produce:
	// its seed is non-empty. This documents that the seed is the missing input.
	const real151 = "bvcR2nfcbw0bPYHPJRO+bpzN01M="
	for _, p := range []Platform{PlatformWindows, PlatformMac, PlatformLinux} {
		if BrowserValidation(ChromeAPIKey(p), ua) == real151 {
			t.Errorf("empty-seed %s unexpectedly reproduced the real 151 value; the seed assumption is wrong", p)
		}
	}
}

// TestApplyGoogleHeadersScope is the important one: these headers must reach
// Google origins over HTTPS and nothing else. Sending them anywhere Chrome
// would not is a stronger tell than omitting them.
func TestApplyGoogleHeadersScope(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://www.google.com/search?q=x", true},
		{"https://play.google.com/store", true},
		{"https://fonts.gstatic.com/s/font.woff2", true},
		{"https://www.google.co.uk/", true},
		{"http://www.google.com/", false},  // http, not https
		{"https://example.com/", false},    // not Google
		{"https://tls.peet.ws/api", false}, // not Google
		{"https://google.evil.com/", false},
	}

	tr := &browserTransport{
		defaultHeaders: http.Header{"user-agent": {"ua"}},
		googleHeaders:  &GoogleHeaders{ClientData: "CM6XywE=", Validation: "v", Year: "2026"},
	}

	for _, tc := range cases {
		req, err := http.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatalf("new request %s: %v", tc.url, err)
		}
		tr.applyGoogleHeaders(req)

		got := req.Header.Get("x-client-data") != ""
		if got != tc.want {
			t.Errorf("%s: google headers applied = %v, want %v", tc.url, got, tc.want)
		}
		if tc.want && req.Header.Get("x-browser-copyright") != "Copyright 2026 Google LLC. All Rights Reserved." {
			t.Errorf("%s: copyright = %q", tc.url, req.Header.Get("x-browser-copyright"))
		}
	}
}

// TestApplyGoogleHeadersKeepsCallerValues checks that an explicitly set header
// is never overwritten.
func TestApplyGoogleHeadersKeepsCallerValues(t *testing.T) {
	tr := &browserTransport{
		defaultHeaders: http.Header{"user-agent": {"ua"}},
		googleHeaders:  &GoogleHeaders{ClientData: "CM6XywE=", Year: "2026"},
	}
	req, _ := http.NewRequest("GET", "https://www.google.com/", nil)
	req.Header.Set("x-client-data", "mine")

	tr.applyGoogleHeaders(req)

	if got := req.Header.Get("x-client-data"); got != "mine" {
		t.Errorf("x-client-data = %q, want the caller's value %q", got, "mine")
	}
}

// TestGoogleHeadersDisabledByDefault confirms a preset with no option set sends
// none of them, so ordinary traffic is unchanged.
func TestGoogleHeadersDisabledByDefault(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "152.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	tr, ok := c.httpClient.Transport.(*browserTransport)
	if !ok {
		t.Fatalf("transport is %T, want *browserTransport", c.httpClient.Transport)
	}
	if tr.googleHeaders != nil {
		t.Error("google headers are enabled without WithGoogleHeaders")
	}

	req, _ := http.NewRequest("GET", "https://www.google.com/", nil)
	tr.applyGoogleHeaders(req)
	if req.Header.Get("x-client-data") != "" || req.Header.Get("x-browser-channel") != "" {
		t.Error("google headers were attached without the option")
	}
}

// TestWithGoogleHeadersWiring checks the option reaches the transport.
func TestWithGoogleHeadersWiring(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "152.0.0.0", "mac",
		WithGoogleHeaders(GoogleHeaders{ClientData: "CM6XywE="}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	tr := c.httpClient.Transport.(*browserTransport)
	if tr.googleHeaders == nil {
		t.Fatal("googleHeaders not wired into the transport")
	}
	if tr.googleHeaders.ClientData != "CM6XywE=" {
		t.Errorf("ClientData = %q", tr.googleHeaders.ClientData)
	}
}
