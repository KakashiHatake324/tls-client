package tlsclient

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	http "github.com/saucesteals/fhttp"
)

type peetResponse struct {
	HTTPVersion string `json:"http_version"`
	TLS         struct {
		Ciphers              []string `json:"ciphers"`
		TLSVersionNegotiated string   `json:"tls_version_negotiated"`
		JA3                  string   `json:"ja3"`
		JA3Hash              string   `json:"ja3_hash"`
		JA4                  string   `json:"ja4"`
		PeetprintHash        string   `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint string `json:"akamai_fingerprint"`
		SentFrames        []struct {
			FrameType string   `json:"frame_type"`
			Settings  []string `json:"settings,omitempty"`
			Increment int      `json:"increment,omitempty"`
			Headers   []string `json:"headers,omitempty"`
			Flags     []string `json:"flags,omitempty"`
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
		t.Fatalf("do request: %v", err)
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

func TestPresetChrome145(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("chrome", "145.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.TLS.TLSVersionNegotiated != "772" {
		t.Errorf("tls version = %q, want 772", pr.TLS.TLSVersionNegotiated)
	}

	if pr.HTTPVersion != "h2" {
		t.Errorf("http_version = %q, want h2", pr.HTTPVersion)
	}

	// Chrome peetprint should match real Chrome
	if pr.TLS.PeetprintHash != "1d4ffe9b0e34acac0bd883fa7f79d7b5" {
		t.Errorf("peetprint_hash = %q, want 1d4ffe9b0e34acac0bd883fa7f79d7b5", pr.TLS.PeetprintHash)
	}

	// JA4 should match real Chrome (stable across extension shuffling)
	if pr.TLS.JA4 != "t13d1516h2_8daaf6152771_d8a2da3f94cd" {
		t.Errorf("ja4 = %q, want t13d1516h2_8daaf6152771_d8a2da3f94cd", pr.TLS.JA4)
	}

	// HTTP/2 SETTINGS should match Chrome (HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144)
	akamai := pr.HTTP2.AkamaiFingerprint
	if !strings.HasPrefix(akamai, "1:65536;2:0;4:6291456;6:262144") {
		t.Errorf("akamai fingerprint = %q, want prefix 1:65536;2:0;4:6291456;6:262144", akamai)
	}

	// Pseudo-header order should be m,a,s,p (Chrome order)
	if len(pr.HTTP2.SentFrames) >= 3 {
		headers := pr.HTTP2.SentFrames[2].Headers
		if len(headers) >= 4 {
			if !strings.HasPrefix(headers[0], ":method") ||
				!strings.HasPrefix(headers[1], ":authority") ||
				!strings.HasPrefix(headers[2], ":scheme") ||
				!strings.HasPrefix(headers[3], ":path") {
				t.Errorf("pseudo-header order = %v, want m,a,s,p", headers[:4])
			}
		}
	}

	t.Logf("JA3: %s", pr.TLS.JA3)
	t.Logf("JA3 Hash: %s", pr.TLS.JA3Hash)
	t.Logf("JA4: %s", pr.TLS.JA4)
	t.Logf("Peetprint Hash: %s", pr.TLS.PeetprintHash)
	t.Logf("Akamai: %s", akamai)
}

func TestPresetFirefox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("firefox", "120.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.HTTPVersion != "h2" {
		t.Errorf("http_version = %q, want h2", pr.HTTPVersion)
	}

	t.Logf("JA3: %s", pr.TLS.JA3)
	t.Logf("JA4: %s", pr.TLS.JA4)
	t.Logf("Akamai: %s", pr.HTTP2.AkamaiFingerprint)
}

func TestJA3Chrome145(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	chrome145JA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0"

	c, err := NewClientWithJA3(chrome145JA3)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.HTTPVersion != "h2" {
		t.Errorf("http_version = %q, want h2", pr.HTTPVersion)
	}

	if pr.TLS.JA3 != chrome145JA3 {
		t.Errorf("JA3 mismatch:\n  got:  %s\n  want: %s", pr.TLS.JA3, chrome145JA3)
	}

	// HTTP/2 should use Chrome settings (even in JA3 mode)
	akamai := pr.HTTP2.AkamaiFingerprint
	if !strings.HasPrefix(akamai, "1:65536;2:0;4:6291456;6:262144") {
		t.Errorf("akamai fingerprint = %q, want prefix 1:65536;2:0;4:6291456;6:262144", akamai)
	}

	t.Logf("JA3: %s", pr.TLS.JA3)
	t.Logf("JA3 Hash: %s", pr.TLS.JA3Hash)
	t.Logf("Akamai: %s", akamai)
}

func TestClientClose(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "145.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.Close()
}
