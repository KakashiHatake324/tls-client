package tlsclient

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// ja3n normalizes a JA3 string by sorting its extension list and returns the
// normalized string along with its MD5.
//
// Raw JA3 is not a stable identifier for any browser that shuffles extensions
// (Chrome 110+), so reference values captured from real browsers are compared
// in normalized JA3N form instead.
func ja3n(ja3 string) (string, string) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return ja3, ""
	}
	var nums []int
	for _, e := range strings.Split(parts[2], "-") {
		if n, err := strconv.Atoi(e); err == nil {
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	strs := make([]string, len(nums))
	for i, n := range nums {
		strs[i] = strconv.Itoa(n)
	}
	parts[2] = strings.Join(strs, "-")
	norm := strings.Join(parts, ",")
	return norm, fmt.Sprintf("%x", md5.Sum([]byte(norm)))
}

func hasCurve(spec *utls.ClientHelloSpec, want utls.CurveID) bool {
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.SupportedCurvesExtension); ok {
			for _, c := range e.Curves {
				if c == want {
					return true
				}
			}
		}
	}
	return false
}

func hasCipher(spec *utls.ClientHelloSpec, want uint16) bool {
	for _, cs := range spec.CipherSuites {
		if cs == want {
			return true
		}
	}
	return false
}

// TestFirefoxCipherListByVersion pins the cipher-list boundary: Firefox 151
// dropped the ECDSA-CBC suite 49161, taking the list from 17 entries to 16.
func TestFirefoxCipherListByVersion(t *testing.T) {
	cases := []struct {
		major     int
		wantCount int
		want49161 bool
	}{
		{134, 17, true},
		{150, 17, true},
		{151, 16, false},
		{160, 16, false},
	}

	for _, tc := range cases {
		spec := firefox120TLSSpec(tc.major, PlatformMac)
		if got := len(spec.CipherSuites); got != tc.wantCount {
			t.Errorf("firefox %d: %d ciphers, want %d", tc.major, got, tc.wantCount)
		}
		got49161 := hasCipher(spec, utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
		if got49161 != tc.want49161 {
			t.Errorf("firefox %d: has 49161 = %v, want %v", tc.major, got49161, tc.want49161)
		}
	}
}

// TestFirefoxPostQuantumByVersion pins the X25519MLKEM768 boundary: desktop
// Firefox offers it from 132, Firefox for Android does not offer it at all.
func TestFirefoxPostQuantumByVersion(t *testing.T) {
	cases := []struct {
		major    int
		platform Platform
		wantPQ   bool
	}{
		{131, PlatformMac, false},
		{132, PlatformMac, true},
		{151, PlatformMac, true},
		{151, PlatformWindows, true},
		{151, PlatformLinux, true},
		{151, PlatformAndroid, false},
	}

	for _, tc := range cases {
		spec := firefox120TLSSpec(tc.major, tc.platform)
		if got := hasCurve(spec, utls.X25519MLKEM768); got != tc.wantPQ {
			t.Errorf("firefox %d/%s: has X25519MLKEM768 = %v, want %v",
				tc.major, tc.platform, got, tc.wantPQ)
		}
	}
}

// TestPresetFirefox151Live checks Firefox 151 against a real Firefox 151.0.3
// capture on both JA4 and JA3N. Both are needed: JA4 does not encode
// supported_groups, so a missing X25519MLKEM768 is invisible in JA4 alone.
func TestPresetFirefox151Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("firefox", "151.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	const (
		wantJA4  = "t13d1617h2_86a278354501_3cbfd9057e0d"
		wantJA3N = "8099457c290ccfe8c6d958826c26b023"
	)
	if pr.TLS.JA4 != wantJA4 {
		t.Errorf("ja4 = %q, want %q", pr.TLS.JA4, wantJA4)
	}
	norm, gotJA3N := ja3n(pr.TLS.JA3)
	if gotJA3N != wantJA3N {
		t.Errorf("ja3n = %q, want %q\n  normalized: %s", gotJA3N, wantJA3N, norm)
	}

	verifyH2(t, pr,
		"1:65536;4:131072;5:16384|12517377|0|m,p,a,s",
		"m,p,a,s",
		true,
	)
}

func hasKeyShare(spec *utls.ClientHelloSpec, want utls.CurveID) bool {
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.KeyShareExtension); ok {
			for _, ks := range e.KeyShares {
				if ks.Group == want {
					return true
				}
			}
		}
	}
	return false
}

// TestSafariPostQuantumByVersion pins the Apple boundary: the 26 releases
// advertise X25519MLKEM768, earlier ones do not, and macOS and iOS agree.
//
// Before this was gated the two platforms disagreed with each other: the macOS
// spec never sent the group and the iOS spec always did, regardless of version.
func TestSafariPostQuantumByVersion(t *testing.T) {
	cases := []struct {
		major  int
		wantPQ bool
	}{
		{16, false},
		{18, false},
		{25, false},
		{26, true},
		{27, true},
	}

	for _, tc := range cases {
		for name, spec := range map[string]*utls.ClientHelloSpec{
			"mac": safariMacTLSSpec(tc.major),
			"ios": iosTLSSpec(tc.major),
		} {
			if got := hasCurve(spec, utls.X25519MLKEM768); got != tc.wantPQ {
				t.Errorf("safari %d/%s: supported_groups has X25519MLKEM768 = %v, want %v",
					tc.major, name, got, tc.wantPQ)
			}
			if got := hasKeyShare(spec, utls.X25519MLKEM768); got != tc.wantPQ {
				t.Errorf("safari %d/%s: key_share has X25519MLKEM768 = %v, want %v",
					tc.major, name, got, tc.wantPQ)
			}
		}
	}
}

// TestSafariPQKeepsGREASEFirst guards the insertion points: Safari leads
// supported_groups and key_share with a GREASE placeholder that must stay first.
func TestSafariPQKeepsGREASEFirst(t *testing.T) {
	for name, spec := range map[string]*utls.ClientHelloSpec{
		"mac": safariMacTLSSpec(26),
		"ios": iosTLSSpec(26),
	} {
		for _, ext := range spec.Extensions {
			switch e := ext.(type) {
			case *utls.SupportedCurvesExtension:
				if e.Curves[0] != utls.CurveID(utls.GREASE_PLACEHOLDER) {
					t.Errorf("%s: curves[0] = %d, want GREASE", name, e.Curves[0])
				}
				if e.Curves[1] != utls.X25519MLKEM768 {
					t.Errorf("%s: curves[1] = %d, want X25519MLKEM768", name, e.Curves[1])
				}
			case *utls.KeyShareExtension:
				if e.KeyShares[0].Group != utls.CurveID(utls.GREASE_PLACEHOLDER) {
					t.Errorf("%s: keyshare[0] = %d, want GREASE", name, e.KeyShares[0].Group)
				}
				if e.KeyShares[1].Group != utls.X25519MLKEM768 {
					t.Errorf("%s: keyshare[1] = %d, want X25519MLKEM768", name, e.KeyShares[1].Group)
				}
			}
		}
	}
}

// TestChromiumOnAppleMobileUsesCurrentOS checks that Chromium presets on iOS and
// iPadOS get the post-quantum group. They are WebKit shells over Apple's TLS
// stack, so the ClientHello follows the OS version, which the Chromium version
// number cannot convey.
func TestChromiumOnAppleMobileUsesCurrentOS(t *testing.T) {
	for _, platform := range []Platform{PlatformIOS, PlatformIPadOS} {
		p, err := chromiumProfile("chrome", "151.0.0.0", "", platform, chromeExperiments{})
		if err != nil {
			t.Fatalf("chrome/%s: %v", platform, err)
		}
		fn, err := p.specFn(platform)
		if err != nil {
			t.Fatalf("chrome/%s specFn: %v", platform, err)
		}
		if !hasCurve(fn(), utls.X25519MLKEM768) {
			t.Errorf("chrome/%s: missing X25519MLKEM768", platform)
		}
	}
}

// TestOkHttpSpecByVersion pins the OkHttp boundary: 5.x uses the TLS 1.3 spec,
// older versions keep uTLS's legacy TLS 1.2-only Android 11 preset.
func TestOkHttpSpecByVersion(t *testing.T) {
	modern := okhttpTLSSpec()
	if len(modern.CipherSuites) != 15 {
		t.Errorf("okhttp spec has %d ciphers, want 15", len(modern.CipherSuites))
	}
	if len(modern.Extensions) != 13 {
		t.Errorf("okhttp spec has %d extensions, want 13", len(modern.Extensions))
	}
	if modern.TLSVersMax != utls.VersionTLS13 {
		t.Errorf("okhttp TLSVersMax = %x, want TLS 1.3", modern.TLSVersMax)
	}

	p, err := okhttpProfile("4.12.0")
	if err != nil {
		t.Fatalf("okhttp 4.12.0: %v", err)
	}
	legacy, err := p.specFn(PlatformAndroid)
	if err != nil {
		t.Fatalf("legacy specFn: %v", err)
	}
	if got := legacy(); got.TLSVersMax == utls.VersionTLS13 {
		t.Error("okhttp 4.x should keep the legacy TLS 1.2 preset")
	}
}

// TestPresetOkHttp5Live checks that OkHttp 5.x negotiates TLS 1.3 and HTTP/2
// and matches the JA3N of a real Android 16 / OkHttp 5.3.0 capture.
//
// Only JA3N is asserted, not JA4: tls.peet.ws excludes the padding extension
// (0x0015) from JA4_c while other JA4 implementations include it, so the JA4_c
// value is tool-dependent even for an identical ClientHello.
func TestPresetOkHttp5Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	c, err := NewClientWithPreset("okhttp", "5.3.0", "android")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.TLS.TLSVersionNegotiated != "772" {
		t.Errorf("tls version = %q, want 772 (TLS 1.3)", pr.TLS.TLSVersionNegotiated)
	}
	if pr.HTTPVersion != "h2" {
		t.Errorf("http version = %q, want h2", pr.HTTPVersion)
	}

	const wantJA3N = "ab22845823d9af0946cb87050d0a5679"
	norm, gotJA3N := ja3n(pr.TLS.JA3)
	if gotJA3N != wantJA3N {
		t.Errorf("ja3n = %q, want %q\n  normalized: %s", gotJA3N, wantJA3N, norm)
	}
	if !strings.HasPrefix(pr.TLS.JA4, "t13d1513h2_8daaf6152771_") {
		t.Errorf("ja4 = %q, want t13d1513h2_8daaf6152771_ prefix", pr.TLS.JA4)
	}
}

// TestJA3ModeNegotiatesTLS13 covers the JA3 legacy-version trap: the first JA3
// field is 771 even for TLS 1.3 clients, so taking it literally capped the
// handshake at TLS 1.2 and produced a t12d JA4 that no browser emits.
func TestJA3ModeNegotiatesTLS13(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	chromeJA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0"

	c, err := NewClientWithJA3(chromeJA3)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	pr := fetchPeet(t, c)

	if pr.TLS.TLSVersionNegotiated != "772" {
		t.Errorf("tls version = %q, want 772 (TLS 1.3)", pr.TLS.TLSVersionNegotiated)
	}
	if !strings.HasPrefix(pr.TLS.JA4, "t13d") {
		t.Errorf("ja4 = %q, want t13d prefix", pr.TLS.JA4)
	}
	// The requested JA3 must still round-trip: offering 1.3 through
	// supported_versions leaves the legacy_version field at 771.
	if pr.TLS.JA3 != chromeJA3 {
		t.Errorf("JA3 no longer round-trips:\n  got:  %s\n  want: %s", pr.TLS.JA3, chromeJA3)
	}
}
