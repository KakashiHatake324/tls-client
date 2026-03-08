package tlsclient

import (
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	http "github.com/saucesteals/fhttp"
	http2 "github.com/saucesteals/fhttp/http2"
)

// Platform represents the OS the browser is running on.
type Platform string

const (
	PlatformWindows Platform = "win"
	PlatformMac     Platform = "mac"
	PlatformLinux   Platform = "linux"
	PlatformIOS     Platform = "ios"
	PlatformIPadOS  Platform = "ipados"
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

// ---------------------------------------------------------------------------
// Chromium (Chrome, Edge, Brave)
// ---------------------------------------------------------------------------

func chromiumProfile(brand, version string) (*browserProfile, error) {
	majorStr, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, err
	}
	if majorNum < 100 {
		return nil, fmt.Errorf("chromium %s: minimum supported version is 100", version)
	}

	helloID := chromiumTLSHelloID(majorNum)
	if _, err := utls.UTLSIdToSpec(helloID); err != nil {
		return nil, fmt.Errorf("chromium %s: %w", version, err)
	}

	return &browserProfile{
		h2: chromiumH2Profile(majorNum),
		specFn: func(_ Platform) (func() *utls.ClientHelloSpec, error) {
			return newSpecFunc(helloID), nil
		},
		headerFn: chromiumHeaders(brand, version, majorStr, majorNum),
	}, nil
}

func chromiumTLSHelloID(v int) utls.ClientHelloID {
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
	case v < 131:
		return utls.HelloChrome_120
	case v < 133:
		return utls.HelloChrome_131
	default:
		return utls.HelloChrome_133
	}
}

func chromiumH2Profile(v int) *h2Profile {
	p := &h2Profile{
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
		MaxHeaderListSize: 262144,
		InitialWindowSize: 6291456,
		HeaderTableSize:   65536,
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
	default:
		p.Settings = []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	}

	return p
}

func chromiumHeaders(brand, version, majorStr string, majorNum int) func(Platform) (http.Header, error) {
	return func(p Platform) (http.Header, error) {
		var uaPlatform, hintPlatform string

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
		default:
			return nil, fmt.Errorf("chromium on %s: unsupported platform", p)
		}

		ua := fmt.Sprintf(
			"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
			uaPlatform, version,
		)
		if brand == "Microsoft Edge" {
			ua += fmt.Sprintf(" Edg/%s", version)
		}

		h := http.Header{}
		h.Set("user-agent", ua)
		h.Set("sec-ch-ua", buildSecChUA(brand, majorStr, majorNum))
		h.Set("sec-ch-ua-mobile", "?0")
		h.Set("sec-ch-ua-platform", fmt.Sprintf(`"%s"`, hintPlatform))

		return h, nil
	}
}

// ---------------------------------------------------------------------------
// Firefox
// ---------------------------------------------------------------------------

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
		specFn: func(_ Platform) (func() *utls.ClientHelloSpec, error) {
			return newSpecFunc(helloID), nil
		},
		headerFn: firefoxHeaders(version),
	}, nil
}

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
		var uaPlatform string
		switch p {
		case PlatformWindows:
			uaPlatform = "Windows NT 10.0; Win64; x64"
		case PlatformMac:
			uaPlatform = "Macintosh; Intel Mac OS X 10.15"
		case PlatformLinux:
			uaPlatform = "X11; Linux x86_64"
		default:
			return nil, fmt.Errorf("firefox on %s: unsupported platform", p)
		}

		h := http.Header{}
		h.Set("user-agent", fmt.Sprintf(
			"Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s",
			uaPlatform, version, version,
		))
		return h, nil
	}
}

// ---------------------------------------------------------------------------
// Safari
// ---------------------------------------------------------------------------

const settingEnableConnectProtocol = http2.SettingID(0x8)

func safariProfile(version string) (*browserProfile, error) {
	_, majorNum, err := parseMajor(version)
	if err != nil {
		return nil, err
	}
	if majorNum < 16 {
		return nil, fmt.Errorf("safari %s: minimum supported version is 16", version)
	}

	return &browserProfile{
		h2: safariH2Profile(),
		specFn: func(p Platform) (func() *utls.ClientHelloSpec, error) {
			switch p {
			case PlatformIOS:
				return newSpecFunc(utls.HelloIOS_14), nil
			case PlatformMac, PlatformIPadOS:
				return newSpecFunc(utls.HelloSafari_16_0), nil
			default:
				return nil, fmt.Errorf("safari on %s: unsupported platform", p)
			}
		},
		headerFn: safariHeaders(version),
	}, nil
}

func safariH2Profile() *h2Profile {
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

// ---------------------------------------------------------------------------
// sec-ch-ua generation (Chromium's GREASE brand algorithm)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
