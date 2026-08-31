package tlsclient

import (
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	http "github.com/saucesteals/fhttp"
	http2 "github.com/saucesteals/fhttp/http2"
)

// currentChromeMajor is the latest Chrome stable major version this package has
// been verified against (152, stable since 2026-08-25). Used as the default
// when no explicit version is available (e.g. JA3 mode). Every version from 120
// up shares the same HTTP/2 profile, so bumping this is documentation rather
// than a behavior change.
const currentChromeMajor = 152

// chromiumModernSpecFrom is the first Chromium major version that sends the
// current ClientHello shape: MLKEM768 key share, ALPS codepoint 17613, GREASE
// ECH, brotli certificate compression. Everything from here up to and including
// currentChromeMajor shares one spec; see chrome133TLSSpec.
const chromiumModernSpecFrom = 132

// Platform represents the OS the browser is running on.
type Platform string

const (
	PlatformWindows Platform = "win"
	PlatformMac     Platform = "mac"
	PlatformLinux   Platform = "linux"
	PlatformIOS     Platform = "ios"
	PlatformIPadOS  Platform = "ipados"
	PlatformAndroid Platform = "android"
)

// h2Profile holds HTTP/2 frame-level settings that distinguish browsers.
type h2Profile struct {
	Settings          []http2.Setting
	PseudoHeaderOrder []string
	MaxHeaderListSize uint32
	InitialWindowSize uint32
	HeaderTableSize   uint32
	ConnectionFlow    uint32
	HeaderPriority    *http2.PriorityParam
}

// browserProfile bundles TLS + HTTP/2 + header configuration for a browser.
type browserProfile struct {
	h2       *h2Profile
	specFn   func(Platform) (func() *utls.ClientHelloSpec, error)
	headerFn func(Platform) (http.Header, error)
}

const (
	settingEnableConnectProtocol        = http2.SettingID(0x8)
	settingNoRFC7540Priorities          = http2.SettingID(0x9)
	fakeTLSECDHERSAWith3DES      uint16 = 0xc012
)

// =====================================================================
// Chromium (Chrome, Edge, Brave)
// =====================================================================

// chromiumProfile builds a profile for any Chromium-based browser.
// Version-specific TLS is selected based on the real browser evolution.
// On iOS/iPadOS, the TLS fingerprint uses Apple's WebKit stack and
// the HTTP/2 profile uses iOS settings (not Chrome desktop).
func chromiumProfile(brand, version, osVersion string, platform Platform, exp chromeExperiments) (*browserProfile, error) {
	majorStr, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, err
	}
	if majorNum < 100 {
		return nil, fmt.Errorf("chromium %s: minimum supported version is 100", version)
	}

	isAppleMobile := platform == PlatformIOS || platform == PlatformIPadOS
	isAndroid := platform == PlatformAndroid

	var h2 *h2Profile
	if isAppleMobile {
		h2 = iosH2Profile()
	} else {
		h2 = chromiumH2Profile(majorNum)
	}

	if majorNum < chromiumModernSpecFrom && !isAppleMobile {
		id := chromiumTLSHelloID(majorNum, isAndroid)
		if _, err := utls.UTLSIdToSpec(id); err != nil {
			return nil, fmt.Errorf("chromium %s: unsupported TLS preset: %w", version, err)
		}
	}

	return &browserProfile{
		h2: h2,
		specFn: func(p Platform) (func() *utls.ClientHelloSpec, error) {
			if p == PlatformIOS || p == PlatformIPadOS {
				return newIOSSpecFunc(currentAppleMajor), nil
			}
			if majorNum >= chromiumModernSpecFrom {
				return newChrome133SpecFunc(majorNum, exp)
			}
			if exp.any() {
				return nil, fmt.Errorf("chromium %s: WithTrustAnchors/WithMLDSA/WithoutMLDSA require version %d or newer",
					version, chromiumModernSpecFrom)
			}
			id := chromiumTLSHelloID(majorNum, isAndroid)
			return newSpecFunc(id), nil
		},
		headerFn: chromiumHeaders(brand, version, osVersion, majorStr, majorNum),
	}, nil
}

// chromiumTLSHelloID selects the correct utls preset based on version and platform.
//
// Timeline of real Chrome TLS changes:
//
//	120-123: curves 29-23-24, ALPS 17513, padding ext 21
//	124-130 desktop: added X25519Kyber768 (25497), dropped padding
//	124-130 Android: still 29-23-24 (no PQ), no padding
//	131 desktop: Kyber replaced by MLKEM768 (4588), ALPS 17513
//	131 Android: still 29-23-24 (no MLKEM768), ALPS 17513
//	132+ all platforms: MLKEM768 (4588), new ALPS 17613, identical desktop/Android
//	141+: trust_anchors (0xca34) available behind a Finch trial; a Chromium
//	      145.0.7568.0 build does send it, stable Chrome 151 does not, so it
//	      stays opt-in through WithTrustAnchors
//	150+: ML-DSA signature schemes advertised BY DEFAULT, ahead of the classical
//	      algorithms. See chromeMLDSAFrom; override with WithoutMLDSA.
//	152: no further ClientHello change found. The new PreferSlowKEXAlgorithms
//	     and PreferSlowCiphers enterprise policies only reorder algorithms when
//	     an administrator sets them, so the default hello is unaffected.
//
// The extension and cipher lists have been stable since 132, so 132 through 152
// share one spec; only signature_algorithms varies, at the 150 boundary.
func chromiumTLSHelloID(v int, isAndroid bool) utls.ClientHelloID {
	switch {
	case v < 102:
		return utls.HelloChrome_100
	case v < 106:
		return utls.HelloChrome_102
	case v < 112:
		return utls.HelloChrome_106_Shuffle
	case v < 114:
		return utls.HelloChrome_112_PSK_Shuf
	case v < 115:
		return utls.HelloChrome_114_Padding_PSK_Shuf
	case v < 120:
		return utls.HelloChrome_115_PQ
	case v < 124:
		return utls.HelloChrome_120
	case v < 131:
		if isAndroid {
			return utls.HelloChrome_120
		}
		return utls.HelloChrome_120_PQ
	case v < chromiumModernSpecFrom:
		if isAndroid {
			return utls.HelloChrome_120
		}
		return utls.HelloChrome_131
	default: // 132 through 152
		return utls.HelloChrome_133
	}
}

// chromiumH2Profile returns the correct HTTP/2 settings for the given Chrome version.
func chromiumH2Profile(v int) *h2Profile {
	p := &h2Profile{
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		MaxHeaderListSize: 262144,
		InitialWindowSize: 6291456,
		HeaderTableSize:   65536,
		ConnectionFlow:    15663105,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		},
	}

	switch {
	case v < 107:
		p.Settings = []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 100000},
		}
		p.MaxHeaderListSize = 100000
	case v < 120:
		p.Settings = []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	default: // 120+
		p.Settings = []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	}

	return p
}

func chromiumHeaders(brand, version, osVersion, majorStr string, majorNum int) func(Platform) (http.Header, error) {
	return func(p Platform) (http.Header, error) {
		var uaPlatform, hintPlatform string
		mobile := false

		switch p {
		case PlatformWindows:
			uaPlatform = "Windows NT 10.0; Win64; x64"
			hintPlatform = "Windows"
		case PlatformMac:
			uaPlatform = "Macintosh; Intel Mac OS X 10_15_7"
			hintPlatform = "macOS"
		case PlatformLinux:
			uaPlatform = "X11; Linux x86_64"
			hintPlatform = "Linux"
		case PlatformAndroid:
			androidVer := resolveOSVersion(osVersion, "14")
			uaPlatform = fmt.Sprintf("Linux; Android %s; Pixel 8", androidVer)
			hintPlatform = "Android"
			mobile = true
		case PlatformIOS:
			mobile = true
			iosVer := resolveOSVersion(osVersion, "18_3")
			iosVer = strings.ReplaceAll(iosVer, ".", "_")
			h := http.Header{}
			h.Set("user-agent", fmt.Sprintf(
				"Mozilla/5.0 (iPhone; CPU iPhone OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/%s Mobile/15E148 Safari/604.1",
				iosVer, version,
			))
			return h, nil
		case PlatformIPadOS:
			iosVer := resolveOSVersion(osVersion, "18_3")
			iosVer = strings.ReplaceAll(iosVer, ".", "_")
			h := http.Header{}
			h.Set("user-agent", fmt.Sprintf(
				"Mozilla/5.0 (iPad; CPU OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/%s Mobile/15E148 Safari/604.1",
				iosVer, version,
			))
			return h, nil
		default:
			return nil, fmt.Errorf("chromium on %s: unsupported platform", p)
		}

		var ua string
		if mobile {
			ua = fmt.Sprintf(
				"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Mobile Safari/537.36",
				uaPlatform, version,
			)
		} else {
			ua = fmt.Sprintf(
				"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
				uaPlatform, version,
			)
		}
		if brand == "Microsoft Edge" {
			ua += fmt.Sprintf(" Edg/%s", version)
		}

		h := http.Header{}
		h.Set("user-agent", ua)
		h.Set("sec-ch-ua", buildSecChUA(brand, majorStr, majorNum))
		if mobile {
			h.Set("sec-ch-ua-mobile", "?1")
		} else {
			h.Set("sec-ch-ua-mobile", "?0")
		}
		h.Set("sec-ch-ua-platform", fmt.Sprintf(`"%s"`, hintPlatform))

		return h, nil
	}
}

// =====================================================================
// Firefox
// =====================================================================

func firefoxProfile(version string) (*browserProfile, error) {
	_, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, err
	}
	if majorNum < 55 {
		return nil, fmt.Errorf("firefox %s: minimum supported version is 55", version)
	}

	helloID := firefoxTLSHelloID(majorNum)
	if _, err := utls.UTLSIdToSpec(helloID); err != nil {
		return nil, fmt.Errorf("firefox %s: %w", version, err)
	}

	return &browserProfile{
		h2: firefoxH2Profile(),
		specFn: func(p Platform) (func() *utls.ClientHelloSpec, error) {
			if majorNum >= 120 {
				return newFirefox120SpecFunc(majorNum, p), nil
			}
			return newSpecFunc(helloID), nil
		},
		headerFn: firefoxHeaders(version),
	}, nil
}

// firefoxPQFrom is the first Firefox major version that offers the hybrid
// post-quantum group X25519MLKEM768 (4588) by default. Mozilla shipped it on
// desktop in Firefox 132 (https://bugzilla.mozilla.org/show_bug.cgi?id=1919097);
// Firefox for Android does not ship it, so it stays desktop-only here.
//
// Verified against a real Firefox 151.0.3 capture whose supported_groups list is
// 4588-29-23-24-25-256-257, giving JA3N 8099457c290ccfe8c6d958826c26b023. JA4
// does not encode supported_groups at all, so omitting this group still produces
// a correct-looking JA4 while JA3, JA3N, and peetprint all diverge.
const firefoxPQFrom = 132

// firefoxUsesPQ reports whether a Firefox build offers X25519MLKEM768.
func firefoxUsesPQ(majorNum int, p Platform) bool {
	if majorNum < firefoxPQFrom {
		return false
	}
	switch p {
	case PlatformAndroid, PlatformIOS, PlatformIPadOS:
		return false
	default:
		return true
	}
}

// firefoxDropsECDSACBCFrom is the first Firefox major version that stops
// offering TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009 / 49161), taking the
// cipher list from 17 entries down to 16.
//
// Verified against a real Firefox 151.0.3 capture, which yields JA4
// t13d1617h2_86a278354501_3cbfd9057e0d. Mozilla tracked the pref flip in
// https://bugzilla.mozilla.org/show_bug.cgi?id=2035801 (milestone "152
// Branch"); the captured stable build already omits the cipher, so the
// observed boundary is used here. Versions 120-150 keep the 17-cipher list.
const firefoxDropsECDSACBCFrom = 151

func firefoxTLSHelloID(v int) utls.ClientHelloID {
	switch {
	case v < 56:
		return utls.HelloFirefox_55
	case v < 63:
		return utls.HelloFirefox_56
	case v < 65:
		return utls.HelloFirefox_63
	case v < 99:
		return utls.HelloFirefox_65
	case v < 102:
		return utls.HelloFirefox_99
	case v < 105:
		return utls.HelloFirefox_102
	case v < 120:
		return utls.HelloFirefox_105
	default:
		return utls.HelloFirefox_120
	}
}

func firefoxH2Profile() *h2Profile {
	return &h2Profile{
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 131072},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
		},
		InitialWindowSize: 131072,
		HeaderTableSize:   65536,
		ConnectionFlow:    12517377,
		HeaderPriority: &http2.PriorityParam{
			StreamDep: 13,
			Exclusive: false,
			Weight:    41, // 0-indexed; actual weight = 42
		},
	}
}

func firefoxHeaders(version string) func(Platform) (http.Header, error) {
	return func(p Platform) (http.Header, error) {
		var ua string
		switch p {
		case PlatformWindows:
			ua = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s) Gecko/20100101 Firefox/%s", version, version)
		case PlatformMac:
			ua = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:%s) Gecko/20100101 Firefox/%s", version, version)
		case PlatformLinux:
			ua = fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:%s) Gecko/20100101 Firefox/%s", version, version)
		case PlatformAndroid:
			ua = fmt.Sprintf("Mozilla/5.0 (Android 14; Mobile; rv:%s) Gecko/%s Firefox/%s", version, version, version)
		default:
			return nil, fmt.Errorf("firefox on %s: unsupported platform", p)
		}

		h := http.Header{}
		h.Set("user-agent", ua)
		return h, nil
	}
}

// =====================================================================
// Safari
// =====================================================================

func safariProfile(version string, platform Platform) (*browserProfile, error) {
	_, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, err
	}
	if majorNum < 16 {
		return nil, fmt.Errorf("safari %s: minimum supported version is 16", version)
	}

	isIOS := platform == PlatformIOS || platform == PlatformIPadOS
	var h2 *h2Profile
	if isIOS {
		h2 = iosH2Profile()
	} else {
		h2 = safariMacH2Profile()
	}

	return &browserProfile{
		h2: h2,
		specFn: func(p Platform) (func() *utls.ClientHelloSpec, error) {
			if p == PlatformIOS || p == PlatformIPadOS {
				return newIOSSpecFunc(majorNum), nil
			}
			return newSafariMacSpecFunc(majorNum), nil
		},
		headerFn: safariHeaders(version),
	}, nil
}

// safariPQFrom is the first Safari major version that offers the hybrid
// post-quantum group X25519MLKEM768. Apple enabled it by default across the 26
// releases (iOS 26, iPadOS 26, macOS Tahoe 26) for everything built on the
// URLSession and Network frameworks, which includes Safari:
// https://support.apple.com/en-gb/122756
//
// Apple aligned Safari's version number with the OS version at 26, so a single
// boundary covers macOS, iOS, and iPadOS.
const safariPQFrom = 26

// currentAppleMajor is the Apple OS version assumed for non-Safari browsers on
// iOS and iPadOS. Chrome, Edge, and Brave there are WebKit shells over Apple's
// TLS stack, so the ClientHello follows the OS rather than the browser, and a
// Chromium version such as 151 says nothing about the OS underneath it.
const currentAppleMajor = 26

// applyApplePQ adds X25519MLKEM768 to a Safari-family spec, matching Apple's 26
// releases: the group joins supported_groups ahead of X25519 and a matching key
// share accompanies the classical X25519 one, so servers without MLKEM768 do not
// force a HelloRetryRequest.
//
// Both lists lead with a GREASE placeholder that has to stay first.
func applyApplePQ(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			at := 0
			if len(e.Curves) > 0 && e.Curves[0] == utls.CurveID(utls.GREASE_PLACEHOLDER) {
				at = 1
			}
			curves := make([]utls.CurveID, 0, len(e.Curves)+1)
			curves = append(curves, e.Curves[:at]...)
			curves = append(curves, utls.X25519MLKEM768)
			curves = append(curves, e.Curves[at:]...)
			e.Curves = curves

		case *utls.KeyShareExtension:
			at := 0
			if len(e.KeyShares) > 0 && e.KeyShares[0].Group == utls.CurveID(utls.GREASE_PLACEHOLDER) {
				at = 1
			}
			shares := make([]utls.KeyShare, 0, len(e.KeyShares)+1)
			shares = append(shares, e.KeyShares[:at]...)
			shares = append(shares, utls.KeyShare{Group: utls.X25519MLKEM768})
			shares = append(shares, e.KeyShares[at:]...)
			e.KeyShares = shares
		}
	}
}

// safariMacH2Profile matches real Safari on macOS (verified against tls.peet.ws).
func safariMacH2Profile() *h2Profile {
	return &h2Profile{
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 4096},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 100},
			{ID: http2.SettingInitialWindowSize, Val: 2097152},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
			{ID: settingEnableConnectProtocol, Val: 1},
		},
		InitialWindowSize: 2097152,
		HeaderTableSize:   4096,
		ConnectionFlow:    10485760,
	}
}

// iosH2Profile matches real iOS 18+/26+ HTTP/2 behavior (WebKit network stack).
// Captured from a real iPhone running Chrome/Safari in 2026.
// Differences from macOS: no HEADER_TABLE_SIZE/MAX_FRAME_SIZE in SETTINGS,
// adds NO_RFC7540_PRIORITIES (setting 9), uses m,s,p,a pseudo-order.
func iosH2Profile() *h2Profile {
	return &h2Profile{
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
		Settings: []http2.Setting{
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 2097152},
			{ID: http2.SettingMaxConcurrentStreams, Val: 100},
			{ID: settingNoRFC7540Priorities, Val: 1},
		},
		InitialWindowSize: 2097152,
		HeaderTableSize:   4096,
		ConnectionFlow:    10485760,
	}
}

func safariHeaders(version string) func(Platform) (http.Header, error) {
	return func(p Platform) (http.Header, error) {
		var ua string
		switch p {
		case PlatformMac:
			ua = fmt.Sprintf(
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
				version,
			)
		case PlatformIOS:
			iosVer := strings.ReplaceAll(version, ".", "_")
			ua = fmt.Sprintf(
				"Mozilla/5.0 (iPhone; CPU iPhone OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1",
				iosVer, version,
			)
		case PlatformIPadOS:
			iosVer := strings.ReplaceAll(version, ".", "_")
			ua = fmt.Sprintf(
				"Mozilla/5.0 (iPad; CPU OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1",
				iosVer, version,
			)
		default:
			return nil, fmt.Errorf("safari on %s: unsupported platform", p)
		}

		h := http.Header{}
		h.Set("user-agent", ua)
		return h, nil
	}
}

// =====================================================================
// Custom iOS TLS spec (built from real iPhone capture, 2026)
// =====================================================================

// iosTLSSpec returns a ClientHelloSpec matching real iOS and iPadOS 18+
// (WebKit/Apple TLS). Built from a real iPhone capture rather than relying on
// utls's outdated HelloIOS_14.
//
// majorNum gates the post-quantum group: iOS 26 and later advertise
// X25519MLKEM768, earlier releases do not. See safariPQFrom.
//
// Key differences from desktop Chrome:
//   - Cipher order: 4866-4867-4865 (not 4865-4866-4867)
//   - Uses zlib cert compression (not brotli)
//   - Includes P-521 in curves
//   - No ECH, no ALPS, no padding
//   - Duplicate PSSWithSHA384 in sig algs (real iOS behavior)
//   - rsa_pkcs1_sha1 at end of sig algs
func iosTLSSpec(majorNum int) *utls.ClientHelloSpec {
	spec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			fakeTLSECDHERSAWith3DES,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{
				Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli, utls.CertCompressionZlib},
			},
			&utls.UtlsGREASEExtension{},
		},
	}

	if majorNum >= safariPQFrom {
		applyApplePQ(spec)
	}

	return spec
}

func newIOSSpecFunc(majorNum int) func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		return iosTLSSpec(majorNum)
	}
}

// =====================================================================
// Custom Chrome 132+ TLS spec (desktop + Android, identical)
// =====================================================================

// chrome133TLSSpec matches real Chrome 132 through 152 on desktop and Android.
// MLKEM768 (4588), new ALPS (17613), ECH, brotli compression, extension shuffling.
//
// The cipher list, extension set, and supported_groups are identical across that
// whole range, so every version shares one JA3N:
//
//	771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
//	0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0
//	JA3N hash: 8e19337e7524d2573be54efb2b0784c9
//
// signature_algorithms is the one part that moves, at Chrome 150, which splits
// the range into two JA4s:
//
//	132-149: t13d1516h2_8daaf6152771_d8a2da3f94cd  peetprint 1d4ffe9b0e34acac0bd883fa7f79d7b5
//	150+:    t13d1516h2_8daaf6152771_806a8c22fdea  peetprint 67c3e9111bed9e7f03d2f21d6d88994b
//
// The 150+ values come from a live capture of Chrome 151.0.7922.174 on macOS
// (2026-08-30, identical headed and headless). Note that JA3 and JA3N cannot see
// this change at all — they do not encode signature algorithms — so a JA3N-only
// check reports a match for a client that no longer looks like Chrome.
//
// uTLS HelloChrome_Auto still emits the pre-150 shape, so it is no longer a
// current-Chrome fingerprint on its own.
//
// Chrome 141+ can additionally send trust_anchors (0xca34) behind a Finch trial.
// Stable Chrome 151 does not send it, so it stays opt-in via WithTrustAnchors.
func chrome133TLSSpec(majorNum int, exp chromeExperiments) (*utls.ClientHelloSpec, error) {
	trustAnchors, err := exp.trustAnchorsExtension()
	if err != nil {
		return nil, err
	}

	exts := []utls.TLSExtension{
		&utls.UtlsGREASEExtension{},
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.GREASE_PLACEHOLDER,
			utls.X25519MLKEM768,
			utls.X25519,
			utls.CurveP256,
			utls.CurveP384,
		}},
		&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: exp.signatureAlgorithms(majorNum, []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}),
		},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519MLKEM768},
			{Group: utls.X25519},
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		&utls.SupportedVersionsExtension{Versions: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}},
		&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
			utls.CertCompressionBrotli,
		}},
		&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
	}

	// Must be inserted ahead of the trailing GREASE extension: the shuffle
	// treats GREASE as positionally invariant, so anything appended after it
	// would pin GREASE off the end of the list.
	if trustAnchors != nil {
		exts = append(exts, trustAnchors)
	}
	exts = append(exts, utls.BoringGREASEECH(), &utls.UtlsGREASEExtension{})

	return &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions:         utls.ShuffleChromeTLSExtensions(exts),
	}, nil
}

func newChrome133SpecFunc(majorNum int, exp chromeExperiments) (func() *utls.ClientHelloSpec, error) {
	// Build once up front so a malformed trust anchor ID surfaces as a client
	// construction error rather than a silent fallback at handshake time.
	if _, err := chrome133TLSSpec(majorNum, exp); err != nil {
		return nil, err
	}
	return func() *utls.ClientHelloSpec {
		spec, err := chrome133TLSSpec(majorNum, exp)
		if err != nil {
			return nil
		}
		return spec
	}, nil
}

// =====================================================================
// Custom Firefox 120+ TLS spec
// =====================================================================

// firefox120TLSSpec matches real Firefox 120+ on all platforms.
// Firefox does NOT shuffle extensions. Cipher order differs from Chrome.
// Includes delegated_credentials (34), record_size_limit (28), ECH, brotli.
// Curves include ffdhe groups (256, 257). No ALPS.
//
// majorNum and platform select two version-dependent details: 151+ drops the
// ECDSA-CBC suite 49161, and 132+ on desktop offers the hybrid post-quantum
// group X25519MLKEM768. See firefoxDropsECDSACBCFrom and firefoxPQFrom.
//
// JA3N (120-131): 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,
//
//	0-5-10-11-13-16-23-27-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0
//
// Verified live for 151 desktop: JA4 t13d1617h2_86a278354501_3cbfd9057e0d,
// JA3N 8099457c290ccfe8c6d958826c26b023.
func firefox120TLSSpec(majorNum int, platform Platform) *utls.ClientHelloSpec {
	spec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.CurveID(256), // ffdhe2048
				utls.CurveID(257), // ffdhe3072
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.ECDSAWithSHA1,
				},
			},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.SCTExtension{},
			utls.BoringGREASEECH(),
		},
	}

	if majorNum >= firefoxDropsECDSACBCFrom {
		filtered := make([]uint16, 0, len(spec.CipherSuites))
		for _, cs := range spec.CipherSuites {
			if cs == utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
				continue
			}
			filtered = append(filtered, cs)
		}
		spec.CipherSuites = filtered
	}

	if firefoxUsesPQ(majorNum, platform) {
		for _, ext := range spec.Extensions {
			switch e := ext.(type) {
			case *utls.SupportedCurvesExtension:
				e.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, e.Curves...)
			case *utls.KeyShareExtension:
				// NSS sends a share for the hybrid group plus a classical
				// X25519 fallback, so servers without MLKEM768 do not force a
				// HelloRetryRequest.
				e.KeyShares = []utls.KeyShare{
					{Group: utls.X25519MLKEM768},
					{Group: utls.X25519},
				}
			}
		}
	}

	return spec
}

func newFirefox120SpecFunc(majorNum int, platform Platform) func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		return firefox120TLSSpec(majorNum, platform)
	}
}

// =====================================================================
// Custom Safari macOS TLS spec
// =====================================================================

// safariMacTLSSpec matches real Safari 16+ on macOS.
// Uses zlib compression (not brotli), includes padding (21), no ECH, no ALPS.
// GREASE throughout. Extension order is fixed (no shuffling).
//
// majorNum gates the post-quantum group: Safari 26 on macOS Tahoe 26 and later
// advertise X25519MLKEM768, earlier releases do not. See safariPQFrom.
//
// JA3N: 771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-
//
//	157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0
func safariMacTLSSpec(majorNum int) *utls.ClientHelloSpec {
	spec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS10,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			fakeTLSECDHERSAWith3DES,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithSHA1,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli, utls.CertCompressionZlib,
			}},
			&utls.UtlsGREASEExtension{},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}

	if majorNum >= safariPQFrom {
		applyApplePQ(spec)
	}

	return spec
}

func newSafariMacSpecFunc(majorNum int) func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		return safariMacTLSSpec(majorNum)
	}
}

// =====================================================================
// Android OkHttp (native Android app fingerprint)
// =====================================================================

// okhttpModernFrom is the first OkHttp major version that uses the TLS 1.3
// spec below. uTLS only ships HelloAndroid_11_OkHttp, which is a TLS 1.2-only
// fingerprint with no ALPN: it cannot negotiate HTTP/2, so clients built on it
// fall back to HTTP/1.1 and carry no Akamai fingerprint at all. Versions below
// this keep that legacy preset; 5.x and up get the modern spec.
const okhttpModernFrom = 5

func okhttpProfile(version string) (*browserProfile, error) {
	_, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, fmt.Errorf("okhttp %s: %w", version, err)
	}

	return &browserProfile{
		h2: okhttpH2Profile(),
		specFn: func(_ Platform) (func() *utls.ClientHelloSpec, error) {
			if majorNum >= okhttpModernFrom {
				return newOkHttpSpecFunc(), nil
			}
			return newSpecFunc(utls.HelloAndroid_11_OkHttp), nil
		},
		headerFn: func(_ Platform) (http.Header, error) {
			h := http.Header{}
			h.Set("user-agent", fmt.Sprintf("okhttp/%s", version))
			return h, nil
		},
	}, nil
}

// okhttpTLSSpec matches OkHttp 5.x on current Android (API 33+), which speaks
// TLS 1.3 and negotiates HTTP/2 via ALPN. Cipher and extension lists match a
// real Android 16 / OkHttp 5.3.0 capture; the same shape was contributed
// upstream as HelloAndroid_16_OkHttp in refraction-networking/utls#399, which
// is not in a tagged uTLS release yet.
//
// Unlike Chrome there is no GREASE, no extension shuffling, no ECH, and no
// certificate compression. Padding is present. The 15 cipher suites are the
// same set Chrome offers, so JA4_b matches Chrome's 8daaf6152771.
//
// Expected JA4: t13d1513h2_8daaf6152771_eca864cca44a
func okhttpTLSSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS12,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

func newOkHttpSpecFunc() func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		return okhttpTLSSpec()
	}
}

func okhttpH2Profile() *h2Profile {
	return &h2Profile{
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		Settings: []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		},
		InitialWindowSize: 6291456,
		HeaderTableSize:   65536,
		ConnectionFlow:    15663105,
	}
}

// =====================================================================
// sec-ch-ua generation (Chromium's GREASE brand algorithm)
// =====================================================================

var (
	legacyGreasyChars = []string{" ", " ", ";"}
	greasyChars       = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greasyVersion     = []string{"8", "99", "24"}
	greasyOrders      = [][]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}
)

func buildSecChUA(brand, majorVersion string, majorNum int) string {
	seed := majorNum
	if majorNum <= 102 {
		seed = 0
	}

	order := greasyOrders[seed%len(greasyOrders)]
	parts := make([]string, 3)

	parts[order[0]] = greasedBrand(seed, majorNum, order)
	parts[order[1]] = fmt.Sprintf(`"Chromium";v="%s"`, majorVersion)
	parts[order[2]] = fmt.Sprintf(`"%s";v="%s"`, brand, majorVersion)

	return strings.Join(parts, ", ")
}

func greasedBrand(seed, majorNum int, order []int) string {
	var brandName, ver string
	switch {
	case majorNum <= 102, majorNum == 104:
		brandName = fmt.Sprintf("%sNot%sA%sBrand",
			legacyGreasyChars[order[0]], legacyGreasyChars[order[1]], legacyGreasyChars[order[2]])
		ver = "99"
	case majorNum == 103:
		brandName = fmt.Sprintf("%sNot%sA%sBrand",
			greasyChars[(seed%(len(greasyChars)-1))+1],
			greasyChars[(seed+1)%len(greasyChars)],
			greasyChars[(seed+2)%len(greasyChars)])
		ver = greasyVersion[seed%len(greasyVersion)]
	default:
		brandName = fmt.Sprintf("Not%sA%sBrand",
			greasyChars[seed%len(greasyChars)],
			greasyChars[(seed+1)%len(greasyChars)])
		ver = greasyVersion[seed%len(greasyVersion)]
	}
	return fmt.Sprintf(`"%s";v="%s"`, brandName, ver)
}

// =====================================================================
// Helpers
// =====================================================================

func resolveOSVersion(provided, fallback string) string {
	if provided != "" {
		return provided
	}
	return fallback
}

func parseMajor(version string) (string, int, error) {
	major := strings.SplitN(version, ".", 2)[0]
	n, err := strconv.Atoi(major)
	if err != nil {
		return "", 0, fmt.Errorf("invalid version %q: %w", version, err)
	}
	return major, n, nil
}

func newSpecFunc(id utls.ClientHelloID) func() *utls.ClientHelloSpec {
	return func() *utls.ClientHelloSpec {
		spec, _ := utls.UTLSIdToSpec(id)
		return &spec
	}
}
