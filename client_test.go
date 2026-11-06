package tlsclient

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"

	http "github.com/saucesteals/fhttp"
	"github.com/saucesteals/fhttp/cookiejar"
)

type peetResponse struct {
	HTTPVersion string `json:"http_version"`
	UserAgent   string `json:"user_agent"`
	TLS         struct {
		Ciphers              []string `json:"ciphers"`
		TLSVersionNegotiated string   `json:"tls_version_negotiated"`
		JA3                  string   `json:"ja3"`
		JA3Hash              string   `json:"ja3_hash"`
		JA4                  string   `json:"ja4"`
		JA4R                 string   `json:"ja4_r"`
		Peetprint            string   `json:"peetprint"`
		PeetprintHash        string   `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		SentFrames            []struct {
			FrameType string   `json:"frame_type"`
			Settings  []string `json:"settings,omitempty"`
			Increment int      `json:"increment,omitempty"`
			Headers   []string `json:"headers,omitempty"`
			Flags     []string `json:"flags,omitempty"`
			Priority  *struct {
				Weight    int `json:"weight"`
				DependsOn int `json:"depends_on"`
				Exclusive int `json:"exclusive"`
			} `json:"priority,omitempty"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

const peetURL = "https://tls.peet.ws/api/all"

func fetchPeet(t *testing.T, c *Client) peetResponse {
	t.Helper()
	req, err := http.NewRequest("GET", peetURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, string(body))
	}

	var pr peetResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, string(body))
	}
	return pr
}

// verifyH2 checks HTTP/2 SETTINGS, WINDOW_UPDATE, pseudo-header order, and priority.
func verifyH2(t *testing.T, pr peetResponse, wantAkamaiPrefix string, wantPseudoOrder string, wantPriority bool) {
	t.Helper()

	if pr.HTTPVersion != "h2" {
		t.Errorf("http_version = %q, want h2", pr.HTTPVersion)
	}

	if !strings.HasPrefix(pr.HTTP2.AkamaiFingerprint, wantAkamaiPrefix) {
		t.Errorf("akamai = %q\n  want prefix: %s", pr.HTTP2.AkamaiFingerprint, wantAkamaiPrefix)
	}

	// Check pseudo-header order from the HEADERS frame
	if len(pr.HTTP2.SentFrames) >= 3 {
		headers := pr.HTTP2.SentFrames[2].Headers
		if len(headers) >= 4 {
			got := pseudoOrder(headers[:4])
			if got != wantPseudoOrder {
				t.Errorf("pseudo-header order = %q, want %q", got, wantPseudoOrder)
			}
		}

		if wantPriority {
			hasPriority := false
			for _, f := range pr.HTTP2.SentFrames[2].Flags {
				if strings.Contains(f, "Priority") {
					hasPriority = true
				}
			}
			if !hasPriority {
				t.Error("HEADERS frame missing Priority flag")
			}
		}
	}
}

func pseudoOrder(headers []string) string {
	var parts []string
	for _, h := range headers {
		key := strings.SplitN(h, ":", 3)[1]
		parts = append(parts, key[0:1])
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// Chrome desktop
// ---------------------------------------------------------------------------

// TestPresetChromeDesktopLive checks Chrome 151, 152, 156, and 157 against real
// Chrome. 151 and 152 are NOT the same: 152 adds the trust_anchors extension and
// a GREASE signature algorithm, so it has its own JA3N and JA4. 156 and 157
// share the 152 shape. Values come from local captures of Chrome 151.0.7922.174
// and Chrome 152.0.7977.65, and from tls.peet.ws readings of a real headed
// Chrome 156.0.8078.x (whose only extra extension was a resumption PSK) and a
// fresh Chrome 157.0.8103.38, all on macOS.
//
// The offline equivalent, which pins the same values without the network, is
// TestChromeModernFingerprint.
func TestPresetChromeDesktopLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cases := []struct {
		version string
		ja4     string
		ja3n    string
		// peetprint includes the signature algorithms. tls.peet.ws renders the
		// GREASE value Chrome 152+ leads with as the literal token "GREASE", so
		// the hash is stable per shape: real Chrome 157 (fresh profile) reported
		// fc97c1cdfb1409c9a9326c1b726d1dee, and the real headed Chrome 156
		// reading differs from it only by the resumption PSK (41) its session
		// carried, so a fresh 152, 156, or 157 hello all hash to that value.
		peetprint string
	}{
		{
			version:   "151.0.0.0",
			ja4:       chromeJA4From150,
			ja3n:      chromeJA3NHash,
			peetprint: "67c3e9111bed9e7f03d2f21d6d88994b",
		},
		{
			version:   "152.0.0.0",
			ja4:       chromeJA4From152,
			ja3n:      chromeJA3NTrustAnchorsHash,
			peetprint: "fc97c1cdfb1409c9a9326c1b726d1dee",
		},
		{
			version:   "156.0.0.0",
			ja4:       chromeJA4From152,
			ja3n:      chromeJA3NTrustAnchorsHash,
			peetprint: "fc97c1cdfb1409c9a9326c1b726d1dee",
		},
		{
			version:   "157.0.0.0",
			ja4:       chromeJA4From152,
			ja3n:      chromeJA3NTrustAnchorsHash,
			peetprint: "fc97c1cdfb1409c9a9326c1b726d1dee",
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			c, err := NewClientWithPreset("chrome", tc.version, "mac")
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			defer c.Close()

			pr := fetchPeet(t, c)

			if pr.TLS.JA4 != tc.ja4 {
				t.Errorf("ja4 = %q, want %q", pr.TLS.JA4, tc.ja4)
			}
			norm, gotJA3N := ja3n(pr.TLS.JA3)
			if gotJA3N != tc.ja3n {
				t.Errorf("ja3n = %q, want %q\n  normalized: %s", gotJA3N, tc.ja3n, norm)
			}
			if tc.peetprint != "" && pr.TLS.PeetprintHash != tc.peetprint {
				t.Errorf("peetprint_hash = %q, want %q\n  got peetprint: %s",
					pr.TLS.PeetprintHash, tc.peetprint, pr.TLS.Peetprint)
			}

			// HTTP/2: Chrome SETTINGS + m,a,s,p + priority
			verifyH2(t, pr,
				"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
				"m,a,s,p",
				true,
			)

			if c.Info.SecChUA == "" {
				t.Error("SecChUA should be set for Chrome")
			}
			if c.Info.SecChUAMobile != "?0" {
				t.Errorf("SecChUAMobile = %q, want ?0", c.Info.SecChUAMobile)
			}

			t.Logf("JA4: %s", pr.TLS.JA4)
			t.Logf("peetprint: %s (%s)", pr.TLS.PeetprintHash, pr.TLS.Peetprint)
			t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
		})
	}
}

// ---------------------------------------------------------------------------
// Chrome mobile Android
// ---------------------------------------------------------------------------

func TestPresetChromeMobileAndroid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "android")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// Same TLS as desktop Chrome 151, including the Chrome 150+ ML-DSA
	// algorithms: the Chrome Enterprise notes list Android among the platforms
	// that got them.
	if pr.TLS.PeetprintHash != "67c3e9111bed9e7f03d2f21d6d88994b" {
		t.Errorf("peetprint_hash = %q, want 67c3e9111bed9e7f03d2f21d6d88994b\n  got peetprint: %s",
			pr.TLS.PeetprintHash, pr.TLS.Peetprint)
	}

	// Same HTTP/2 as desktop Chrome
	verifyH2(t, pr,
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"m,a,s,p",
		true,
	)

	if c.Info.SecChUAMobile != "?1" {
		t.Errorf("SecChUAMobile = %q, want ?1 (mobile)", c.Info.SecChUAMobile)
	}
	if !strings.Contains(c.Info.UserAgent, "Mobile") {
		t.Errorf("UA missing 'Mobile': %s", c.Info.UserAgent)
	}

	t.Logf("UA: %s", c.Info.UserAgent)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// Firefox desktop
// ---------------------------------------------------------------------------

func TestPresetFirefoxMac(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("firefox", "134.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.TLS.TLSVersionNegotiated != "772" {
		t.Errorf("tls version = %q, want 772", pr.TLS.TLSVersionNegotiated)
	}

	// HTTP/2: Firefox SETTINGS + m,p,a,s pseudo-order
	verifyH2(t, pr,
		"1:65536;4:131072;5:16384|12517377|0|m,p,a,s",
		"m,p,a,s",
		true,
	)

	// Firefox has no sec-ch-ua
	if c.Info.SecChUA != "" {
		t.Errorf("SecChUA should be empty for Firefox, got %q", c.Info.SecChUA)
	}

	t.Logf("JA4: %s", pr.TLS.JA4)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// Safari macOS
// ---------------------------------------------------------------------------

func TestPresetSafariMac(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("safari", "18.3", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// macOS Safari uses the original Safari H2 profile
	verifyH2(t, pr,
		"1:4096;2:0;3:100;4:2097152;5:16384;",
		"m,s,p,a",
		false,
	)

	if c.Info.SecChUA != "" {
		t.Errorf("SecChUA should be empty for Safari, got %q", c.Info.SecChUA)
	}
	if !strings.Contains(c.Info.UserAgent, "Safari") {
		t.Errorf("UA missing 'Safari': %s", c.Info.UserAgent)
	}

	t.Logf("JA4: %s", pr.TLS.JA4)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// Safari iOS
// ---------------------------------------------------------------------------

func TestPresetSafariIOS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("safari", "18.3", "ios")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// iOS uses the newer iOS H2 profile with NO_RFC7540_PRIORITIES
	verifyH2(t, pr,
		"2:0;4:2097152;3:100;",
		"m,s,p,a",
		false,
	)

	if !strings.Contains(c.Info.UserAgent, "iPhone") {
		t.Errorf("UA missing 'iPhone': %s", c.Info.UserAgent)
	}

	t.Logf("UA: %s", c.Info.UserAgent)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// Chrome experiment options (trust_anchors, ML-DSA)
// ---------------------------------------------------------------------------

// TestChromeTrustAnchorsLive confirms the trust_anchors extension is accepted
// by a real server and lands in the ClientHello as extension ca34, moving the
// JA4 prefix from t13d1516h2 to t13d1517h2 like Chrome 141+ with the
// TLSTrustAnchorIDs trial active.
func TestChromeTrustAnchorsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithTrustAnchors())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if !strings.HasPrefix(pr.TLS.JA4, "t13d1517h2") {
		t.Errorf("ja4 = %q, want t13d1517h2 prefix (17 extensions)", pr.TLS.JA4)
	}
	if !strings.Contains(pr.TLS.JA4R, "ca34") {
		t.Errorf("ja4_r missing ca34 extension: %s", pr.TLS.JA4R)
	}

	// HTTP/2 is unaffected by the TLS extension.
	verifyH2(t, pr,
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"m,a,s,p",
		true,
	)

	t.Logf("JA4:   %s", pr.TLS.JA4)
	t.Logf("JA4_r: %s", pr.TLS.JA4R)
}

// TestChromeTrustAnchorsWithIDsLive sends a non-empty trust anchor list.
func TestChromeTrustAnchorsWithIDsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac",
		WithTrustAnchors("32473.1", "32473.2.1"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if !strings.Contains(pr.TLS.JA4R, "ca34") {
		t.Errorf("ja4_r missing ca34 extension: %s", pr.TLS.JA4R)
	}
	t.Logf("JA4: %s", pr.TLS.JA4)
}

// TestChromeMLDSALive confirms the ML-DSA signature schemes appear ahead of the
// classical algorithms with no option set at all: real Chrome sends them by
// default from version 150 on.
func TestChromeMLDSALive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// JA4_r lists signature algorithms in wire order after the final underscore.
	if !strings.Contains(pr.TLS.JA4R, "0904,0905,0906") {
		t.Errorf("ja4_r missing ML-DSA schemes in order: %s", pr.TLS.JA4R)
	}
	t.Logf("JA4:   %s", pr.TLS.JA4)
	t.Logf("JA4_r: %s", pr.TLS.JA4R)
}

// TestChromeBothExperimentsLive matches a Chrome build that has the trust
// anchors trial active on top of the default 150+ ML-DSA algorithms.
func TestChromeBothExperimentsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithTrustAnchors())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if !strings.HasPrefix(pr.TLS.JA4, "t13d1517h2") {
		t.Errorf("ja4 = %q, want t13d1517h2 prefix", pr.TLS.JA4)
	}
	if !strings.Contains(pr.TLS.JA4R, "ca34") {
		t.Errorf("ja4_r missing ca34: %s", pr.TLS.JA4R)
	}
	if !strings.Contains(pr.TLS.JA4R, "0904,0905,0906") {
		t.Errorf("ja4_r missing ML-DSA schemes: %s", pr.TLS.JA4R)
	}

	t.Logf("JA4:   %s", pr.TLS.JA4)
	t.Logf("JA4_r: %s", pr.TLS.JA4R)
}

// TestChromeWithoutMLDSALive reproduces the pre-150 Chrome shape, which is what
// a capture from Chrome 132-149 looks like.
func TestChromeWithoutMLDSALive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithoutMLDSA())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.TLS.JA4 != chromeJA4Pre150 {
		t.Errorf("ja4 = %q, want %q", pr.TLS.JA4, chromeJA4Pre150)
	}
	if strings.Contains(pr.TLS.JA4R, "0904") {
		t.Errorf("ja4_r still advertises ML-DSA: %s", pr.TLS.JA4R)
	}
}

// ---------------------------------------------------------------------------
// JA3 with Chrome H2
// ---------------------------------------------------------------------------

func TestJA3Chrome151(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	chrome151JA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0"

	c, err := NewClientWithJA3(chrome151JA3)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// Exact JA3 match (no extension shuffling in JA3 mode)
	if pr.TLS.JA3 != chrome151JA3 {
		t.Errorf("JA3 mismatch:\n  got:  %s\n  want: %s", pr.TLS.JA3, chrome151JA3)
	}

	// HTTP/2 should use Chrome settings
	verifyH2(t, pr,
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"m,a,s,p",
		true,
	)

	t.Logf("JA3 Hash: %s", pr.TLS.JA3Hash)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// JA3 with Firefox H2
// ---------------------------------------------------------------------------

func TestJA3WithFirefoxH2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	firefoxJA3 := "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"

	c, err := NewClientWithJA3(firefoxJA3, WithH2Profile("firefox"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	// HTTP/2 should use Firefox settings
	verifyH2(t, pr,
		"1:65536;4:131072;5:16384|12517377|0|m,p,a,s",
		"m,p,a,s",
		true,
	)

	t.Logf("JA3 Hash: %s", pr.TLS.JA3Hash)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

func TestClientClose(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.Close()
}

func TestClientFromPool(t *testing.T) {
	pool := []BrowserSpec{
		{Browser: "chrome", Version: "151.0.0.0", Platform: "mac"},
		{Browser: "chrome", Version: "151.0.0.0", Platform: "win"},
	}
	c, err := NewClientFromPool(pool)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if c.Info.Browser != "chrome" {
		t.Errorf("browser = %q, want chrome", c.Info.Browser)
	}
	if c.Info.Version != "151.0.0.0" {
		t.Errorf("version = %q, want 151.0.0.0", c.Info.Version)
	}
}

func TestCookieJarEnabled(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if c.Jar() == nil {
		t.Error("cookie jar should be enabled by default")
	}
}

func TestCookieJarDisabled(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithNoCookieJar())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if c.Jar() != nil {
		t.Error("cookie jar should be nil when disabled")
	}
}

func TestCookieJarSetAndGet(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	jar := c.Jar()
	if jar == nil {
		t.Fatal("jar is nil")
	}

	u, _ := url.Parse("https://example.com")

	jar.SetCookies(u, []*http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "lang", Value: "en"},
	})

	cookies := jar.Cookies(u)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	found := map[string]string{}
	for _, c := range cookies {
		found[c.Name] = c.Value
	}

	if found["session"] != "abc123" {
		t.Errorf("session cookie = %q, want abc123", found["session"])
	}
	if found["lang"] != "en" {
		t.Errorf("lang cookie = %q, want en", found["lang"])
	}
}

func TestCookieJarCustom(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new jar: %v", err)
	}

	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithCookieJar(jar))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	u, _ := url.Parse("https://example.com")

	c.Jar().SetCookies(u, []*http.Cookie{
		{Name: "token", Value: "xyz789"},
		{Name: "session", Value: "abc123"},
	})

	cookies := c.Jar().Cookies(u)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	found := map[string]string{}
	for _, ck := range cookies {
		found[ck.Name] = ck.Value
	}
	if found["token"] != "xyz789" {
		t.Errorf("token = %q, want xyz789", found["token"])
	}
	if found["session"] != "abc123" {
		t.Errorf("session = %q, want abc123", found["session"])
	}
}
