package tlsclient

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Offline fingerprint verification.
//
// The live tests in client_test.go send a real handshake to tls.peet.ws and
// read back the JA3/JA4 it observed. That proves the fingerprint end to end but
// needs the network, so it is skipped in -short runs and in CI. The helpers
// below marshal the ClientHello a preset would send and compute JA3, JA3N, and
// JA4 from the raw bytes exactly as a server would, which pins the same values
// with no network at all.

// helloInfo is the subset of a ClientHello the JA3 and JA4 fingerprints cover.
type helloInfo struct {
	legacyVersion uint16
	ciphers       []uint16 // GREASE removed
	extensions    []uint16 // GREASE removed, wire order preserved
	curves        []uint16 // GREASE removed
	pointFormats  []uint8
	sigAlgs       []uint16 // order preserved: JA4_c does not sort these
	alpn          []string
	supportedVers []uint16 // GREASE removed
	hasSNI        bool
}

const (
	extSNI               uint16 = 0x0000
	extSupportedGroups   uint16 = 0x000a
	extECPointFormats    uint16 = 0x000b
	extSigAlgs           uint16 = 0x000d
	extALPN              uint16 = 0x0010
	extSupportedVersions uint16 = 0x002b
)

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// buildClientHello marshals the ClientHello for spec and returns the raw
// handshake message body (the 4-byte handshake header stripped).
func buildClientHello(t *testing.T, spec *utls.ClientHelloSpec) []byte {
	t.Helper()

	// net.Pipe gives a real net.Conn; nothing is written to it because the
	// handshake never runs, only the ClientHello is marshaled.
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	uconn := utls.UClient(client, &utls.Config{ServerName: "tls.peet.ws"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("apply preset: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}

	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) < 4 {
		t.Fatalf("client hello is %d bytes, too short", len(raw))
	}
	// Handshake header: msg_type(1) + length(3).
	if raw[0] == 0x01 {
		return raw[4:]
	}
	return raw
}

// parseClientHello reads the fields JA3 and JA4 are computed from out of a
// ClientHello body, dropping GREASE values as both fingerprints require.
func parseClientHello(b []byte) (helloInfo, error) {
	var h helloInfo
	r := &reader{b: b}

	h.legacyVersion = r.u16()
	r.skip(32) // random
	r.skip(int(r.u8()))

	cipherBytes := r.bytes(int(r.u16()))
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		if c := binary.BigEndian.Uint16(cipherBytes[i:]); !isGREASE(c) {
			h.ciphers = append(h.ciphers, c)
		}
	}

	r.skip(int(r.u8())) // compression methods

	extBytes := r.bytes(int(r.u16()))
	if r.err != nil {
		return h, r.err
	}

	er := &reader{b: extBytes}
	for er.remaining() >= 4 {
		id := er.u16()
		body := er.bytes(int(er.u16()))
		if er.err != nil {
			return h, er.err
		}
		if isGREASE(id) {
			continue
		}
		h.extensions = append(h.extensions, id)

		switch id {
		case extSNI:
			h.hasSNI = true
		case extSupportedGroups:
			br := &reader{b: body}
			curves := br.bytes(int(br.u16()))
			for i := 0; i+1 < len(curves); i += 2 {
				if c := binary.BigEndian.Uint16(curves[i:]); !isGREASE(c) {
					h.curves = append(h.curves, c)
				}
			}
		case extECPointFormats:
			br := &reader{b: body}
			h.pointFormats = br.bytes(int(br.u8()))
		case extSigAlgs:
			br := &reader{b: body}
			algs := br.bytes(int(br.u16()))
			for i := 0; i+1 < len(algs); i += 2 {
				h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(algs[i:]))
			}
		case extALPN:
			br := &reader{b: body}
			list := &reader{b: br.bytes(int(br.u16()))}
			for list.remaining() > 0 {
				h.alpn = append(h.alpn, string(list.bytes(int(list.u8()))))
			}
		case extSupportedVersions:
			br := &reader{b: body}
			vers := br.bytes(int(br.u8()))
			for i := 0; i+1 < len(vers); i += 2 {
				if v := binary.BigEndian.Uint16(vers[i:]); !isGREASE(v) {
					h.supportedVers = append(h.supportedVers, v)
				}
			}
		}
	}

	return h, er.err
}

// ja3 renders the JA3 string: version,ciphers,extensions,curves,point-formats.
func (h helloInfo) ja3() string {
	return strings.Join([]string{
		fmt.Sprint(h.legacyVersion),
		joinU16(h.ciphers, "-"),
		joinU16(h.extensions, "-"),
		joinU16(h.curves, "-"),
		joinU8(h.pointFormats, "-"),
	}, ",")
}

// ja4 renders the JA4 fingerprint (foxio JA4, TCP variant).
func (h helloInfo) ja4() string {
	version := "12"
	switch max := maxVersion(h.supportedVers, h.legacyVersion); max {
	case utls.VersionTLS13:
		version = "13"
	case utls.VersionTLS12:
		version = "12"
	case utls.VersionTLS11:
		version = "11"
	case utls.VersionTLS10:
		version = "10"
	}

	sni := "i"
	if h.hasSNI {
		sni = "d"
	}

	alpn := "00"
	if len(h.alpn) > 0 && h.alpn[0] != "" {
		first := h.alpn[0]
		alpn = string([]byte{first[0], first[len(first)-1]})
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni,
		cap99(len(h.ciphers)), cap99(len(h.extensions)), alpn)

	ciphers := append([]uint16(nil), h.ciphers...)
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	b := truncHash(joinHex(ciphers, ","))

	// JA4_c counts SNI and ALPN in JA4_a but excludes them from the hash, and
	// appends the signature algorithms in their original order.
	exts := make([]uint16, 0, len(h.extensions))
	for _, e := range h.extensions {
		if e == extSNI || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	c := joinHex(exts, ",")
	if len(h.sigAlgs) > 0 {
		c += "_" + joinHex(h.sigAlgs, ",")
	}

	return fmt.Sprintf("%s_%s_%s", a, b, truncHash(c))
}

// truncHash is JA4's hash: the first 12 hex characters of the SHA-256 digest,
// or twelve zeroes for an empty list.
func truncHash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}

func maxVersion(versions []uint16, fallback uint16) uint16 {
	max := uint16(0)
	for _, v := range versions {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return fallback
	}
	return max
}

func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func joinU16(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, sep)
}

func joinU8(vals []uint8, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, sep)
}

func joinHex(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, sep)
}

// reader is a cursor over a byte slice that records the first overrun instead
// of panicking, so a malformed ClientHello surfaces as a test failure.
type reader struct {
	b   []byte
	err error
}

func (r *reader) remaining() int { return len(r.b) }

func (r *reader) fail() {
	if r.err == nil {
		r.err = fmt.Errorf("truncated client hello")
	}
	r.b = nil
}

func (r *reader) u8() uint8 {
	if len(r.b) < 1 {
		r.fail()
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) u16() uint16 {
	if len(r.b) < 2 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.fail()
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int) { r.bytes(n) }

// presetHello builds the ClientHello a preset would actually send and returns
// its parsed contents.
func presetHello(t *testing.T, browser, version string, platform Platform, opts ...Option) helloInfo {
	t.Helper()

	c := &Client{}
	for _, o := range opts {
		o(c)
	}

	profile, err := lookupProfile(browser, version, "", platform, c.experiments)
	if err != nil {
		t.Fatalf("%s %s/%s: %v", browser, version, platform, err)
	}
	specFn, err := profile.specFn(platform)
	if err != nil {
		t.Fatalf("%s %s/%s specFn: %v", browser, version, platform, err)
	}

	info, err := parseClientHello(buildClientHello(t, specFn()))
	if err != nil {
		t.Fatalf("%s %s/%s: parse client hello: %v", browser, version, platform, err)
	}
	return info
}

// fingerprintPreset builds the ClientHello a preset would send and returns its
// JA3, normalized JA3N, JA3N hash, and JA4.
func fingerprintPreset(t *testing.T, browser, version string, platform Platform, opts ...Option) (raw, norm, ja3nHash, ja4 string) {
	t.Helper()

	info := presetHello(t, browser, version, platform, opts...)
	raw = info.ja3()
	norm, ja3nHash = ja3n(raw)
	return raw, norm, ja3nHash, info.ja4()
}

// Reference fingerprints for the Chromium ClientHello shape shipped from Chrome
// 132 onward. The cipher list, extension set, and groups are identical across
// the whole range, so JA3N never moves; signature_algorithms changes at Chrome
// 150, which splits JA4_c in two.
//
// The 150+ values were captured off the wire from Chrome 151.0.7922.174 on
// macOS (2026-08-30), headed and headless, via a local ClientHello dump.
const (
	chromeJA3N = "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281," +
		"4588-29-23-24,0"
	chromeJA3NHash = "8e19337e7524d2573be54efb2b0784c9"

	// Chrome 132-149: classical signature algorithms only.
	chromeJA4Pre150 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	// Chrome 150+: ML-DSA advertised ahead of the classical algorithms.
	chromeJA4From150 = "t13d1516h2_8daaf6152771_806a8c22fdea"
)

// chromeSigAlgsFrom150 is the exact signature_algorithms list real Chrome 151
// sends, in wire order, from the capture referenced above.
var chromeSigAlgsFrom150 = []uint16{
	0x0904, 0x0905, 0x0906, // mldsa44, mldsa65, mldsa87
	0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
}

var chromeSigAlgsPre150 = chromeSigAlgsFrom150[3:]

func wantJA4(major int) string {
	if major >= chromeMLDSAFrom {
		return chromeJA4From150
	}
	return chromeJA4Pre150
}

// TestChromeModernFingerprint pins JA3N and JA4 for every Chromium preset on the
// current ClientHello shape, across the Chrome 150 signature_algorithms boundary.
//
// JA3N is deliberately asserted to be the SAME on both sides of that boundary:
// JA3 does not encode signature algorithms, so it cannot see the ML-DSA change.
// That is why JA4 is pinned alongside it — a JA3N-only check passes for a client
// that no longer matches Chrome.
func TestChromeModernFingerprint(t *testing.T) {
	versions := []struct {
		version string
		major   int
	}{
		{"132.0.0.0", 132},
		{"133.0.0.0", 133},
		{"149.0.0.0", 149},
		{"150.0.0.0", 150},
		{"151.0.0.0", 151},
		{"152.0.0.0", 152},
	}
	platforms := []Platform{PlatformMac, PlatformWindows, PlatformLinux, PlatformAndroid}
	browsers := []string{"chrome", "edge", "brave"}

	for _, browser := range browsers {
		for _, v := range versions {
			for _, platform := range platforms {
				name := fmt.Sprintf("%s/%s/%s", browser, v.version, platform)
				t.Run(name, func(t *testing.T) {
					_, norm, hash, ja4 := fingerprintPreset(t, browser, v.version, platform)
					if norm != chromeJA3N {
						t.Errorf("ja3n = %q, want %q", norm, chromeJA3N)
					}
					if hash != chromeJA3NHash {
						t.Errorf("ja3n hash = %q, want %q", hash, chromeJA3NHash)
					}
					if want := wantJA4(v.major); ja4 != want {
						t.Errorf("ja4 = %q, want %q", ja4, want)
					}
				})
			}
		}
	}
}

// TestChromeMLDSABoundary pins the Chrome 150 signature_algorithms boundary
// itself: 150 and up advertise mldsa44/65/87 ahead of the classical algorithms,
// earlier versions do not, and the classical tail is untouched either way.
func TestChromeMLDSABoundary(t *testing.T) {
	cases := []struct {
		version string
		want    []uint16
	}{
		{"132.0.0.0", chromeSigAlgsPre150},
		{"149.0.0.0", chromeSigAlgsPre150},
		{"150.0.0.0", chromeSigAlgsFrom150},
		{"151.0.0.0", chromeSigAlgsFrom150},
		{"152.0.0.0", chromeSigAlgsFrom150},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			info := presetHello(t, "chrome", tc.version, PlatformMac)
			if !equalU16(info.sigAlgs, tc.want) {
				t.Errorf("signature_algorithms = %v, want %v", info.sigAlgs, tc.want)
			}
		})
	}
}

// TestChromeMLDSAOverrides covers forcing the boundary either way: WithMLDSA on
// an older version, WithoutMLDSA on a newer one.
func TestChromeMLDSAOverrides(t *testing.T) {
	cases := []struct {
		name    string
		version string
		opts    []Option
		want    []uint16
		wantJA4 string
	}{
		{"149-forced-on", "149.0.0.0", []Option{WithMLDSA()}, chromeSigAlgsFrom150, chromeJA4From150},
		{"152-forced-off", "152.0.0.0", []Option{WithoutMLDSA()}, chromeSigAlgsPre150, chromeJA4Pre150},
		{"152-forced-on-is-noop", "152.0.0.0", []Option{WithMLDSA()}, chromeSigAlgsFrom150, chromeJA4From150},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := presetHello(t, "chrome", tc.version, PlatformMac, tc.opts...)
			if !equalU16(info.sigAlgs, tc.want) {
				t.Errorf("signature_algorithms = %v, want %v", info.sigAlgs, tc.want)
			}
			if got := info.ja4(); got != tc.wantJA4 {
				t.Errorf("ja4 = %q, want %q", got, tc.wantJA4)
			}
		})
	}
}

// TestChromeExtensionShufflingVariesJA3 guards the other half of the match:
// Chrome permutes its extensions on every connection, so a preset that emitted
// a fixed raw JA3 would stand out no matter how well JA3N and JA4 line up.
func TestChromeExtensionShufflingVariesJA3(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		raw, norm, _, ja4 := fingerprintPreset(t, "chrome", "152.0.0.0", PlatformMac)
		seen[raw] = true
		if norm != chromeJA3N {
			t.Fatalf("ja3n = %q, want %q", norm, chromeJA3N)
		}
		if ja4 != chromeJA4From150 {
			t.Fatalf("ja4 = %q, want %q", ja4, chromeJA4From150)
		}
	}
	if len(seen) < 2 {
		t.Errorf("raw JA3 was identical across 16 hellos; extension shuffling is not happening")
	}
}

// TestChromeTrustAnchorsFingerprint pins the one genuinely opt-in extension.
// trust_anchors adds extension 51764 (0xca34), moving the JA4 prefix to
// t13d1517h2 and changing JA3N, which — unlike signature algorithms — does cover
// the extension list.
func TestChromeTrustAnchorsFingerprint(t *testing.T) {
	const trustAnchorsJA3N = "771," +
		"4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281," +
		"4588-29-23-24,0"

	cases := []struct {
		name     string
		opts     []Option
		wantJA3N string
		wantJA4  string
	}{
		{"default", nil, chromeJA3N, chromeJA4From150},
		{"trust-anchors", []Option{WithTrustAnchors()}, trustAnchorsJA3N, "t13d1517h2_8daaf6152771_cb7bf5808d99"},
		{"trust-anchors-no-mldsa", []Option{WithTrustAnchors(), WithoutMLDSA()}, trustAnchorsJA3N, "t13d1517h2_8daaf6152771_dcad5a053991"},
		{"no-mldsa", []Option{WithoutMLDSA()}, chromeJA3N, chromeJA4Pre150},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, norm, _, ja4 := fingerprintPreset(t, "chrome", "152.0.0.0", PlatformMac, tc.opts...)
			if norm != tc.wantJA3N {
				t.Errorf("ja3n = %q, want %q", norm, tc.wantJA3N)
			}
			if ja4 != tc.wantJA4 {
				t.Errorf("ja4 = %q, want %q", ja4, tc.wantJA4)
			}
		})
	}
}

// TestChromeSecChUAByVersion covers the identity half of a Chrome 151 or 152
// impersonation: the GREASE brand list is seeded by the major version, so a
// mismatch between the sec-ch-ua brands and the User-Agent is its own tell.
func TestChromeSecChUAByVersion(t *testing.T) {
	// Derived from Chromium's GetUserAgentBrandList: the greasy brand is
	// "Not" + greasyChars[v%11] + "A" + greasyChars[(v+1)%11] + "Brand" at
	// version greasyVersion[v%3], and the three brands are laid out in
	// greasyOrders[v%6].
	//
	//	151: chars[8]="=", chars[9]="?", version[1]="99", order[1]={0,2,1}
	//	152: chars[9]="?", chars[10]="_", version[2]="24", order[2]={1,0,2}
	cases := []struct {
		version string
		want    string
	}{
		{"151.0.0.0", `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`},
		{"152.0.0.0", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
	}

	for _, tc := range cases {
		c, err := NewClientWithPreset("chrome", tc.version, "mac")
		if err != nil {
			t.Fatalf("chrome %s: %v", tc.version, err)
		}
		c.Close()

		if c.Info.SecChUA != tc.want {
			t.Errorf("chrome %s sec-ch-ua = %q, want %q", tc.version, c.Info.SecChUA, tc.want)
		}
		wantUA := "Chrome/" + tc.version + " Safari/537.36"
		if !strings.HasSuffix(c.Info.UserAgent, wantUA) {
			t.Errorf("chrome %s user-agent = %q, want suffix %q", tc.version, c.Info.UserAgent, wantUA)
		}
	}
}

func equalU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
