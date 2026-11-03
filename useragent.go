package tlsclient

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// User-Agent token patterns. Compiled once at init.
var (
	reUAChrome  = regexp.MustCompile(`Chrome/(\d+(?:\.\d+){0,3})`)
	reUACriOS   = regexp.MustCompile(`CriOS/(\d+(?:\.\d+){0,3})`)
	reUAEdge    = regexp.MustCompile(`Edg(?:e|A|iOS)?/(\d+(?:\.\d+){0,3})`)
	reUABrave   = regexp.MustCompile(`Brave/(\d+(?:\.\d+){0,3})`)
	reUAFirefox = regexp.MustCompile(`(?:Firefox|FxiOS)/(\d+(?:\.\d+){0,2})`)
	reUASafari  = regexp.MustCompile(`Version/(\d+(?:\.\d+){0,2})`)
	reUAOkhttp  = regexp.MustCompile(`okhttp/(\d+(?:\.\d+){0,3})`)
	reUAAndroid = regexp.MustCompile(`Android (\d+(?:\.\d+){0,2})`)
	reUAIOSVer  = regexp.MustCompile(`(?:iPhone OS|CPU OS) (\d+(?:[_\.]\d+){0,2})`)
)

// edgeChromiumFrom is the first Edge version built on Chromium. Earlier
// "Edge/" tokens (12-18) are EdgeHTML, a different engine whose version number
// must not be mistaken for a Chromium version: such UAs usually also carry a
// real "Chrome/" token, which is the one worth fingerprinting.
const edgeChromiumFrom = 79

// uaMajor returns the leading major version number from a dotted version
// string, or 0 if it has none.
func uaMajor(version string) int {
	end := strings.IndexByte(version, '.')
	if end < 0 {
		end = len(version)
	}
	n, err := strconv.Atoi(version[:end])
	if err != nil {
		return 0
	}
	return n
}

// ParsedUserAgent describes the browser, version, and platform inferred from
// a User-Agent string.
type ParsedUserAgent struct {
	Browser   string   // chrome, edge, brave, firefox, safari, okhttp
	Version   string   // browser version (e.g. "145.0.0.0", "134.0", "18.3")
	Platform  Platform // win, mac, linux, ios, ipados, android
	OSVersion string   // optional: iOS/iPadOS/Android OS version (e.g. "18.3", "14")
}

// ParseUserAgent inspects a User-Agent string and returns the browser identity
// most appropriate for fingerprinting. The returned struct can be fed back to
// NewClientWithPreset for the same effect as NewClientWithUserAgent.
//
// Notes:
//   - Brave is detected only when the UA explicitly carries a "Brave/" token,
//     which most modern Brave builds omit; without that token it is reported as
//     "chrome" since the underlying TLS/HTTP-2 fingerprint is identical.
//   - Chrome on iOS/iPadOS (CriOS token) is reported as "chrome" with platform
//     set to ios/ipados; the TLS profile switches to the iOS WebKit stack.
//   - Edge on iOS (EdgiOS) is reported as "edge" with platform ios.
func ParseUserAgent(ua string) (ParsedUserAgent, error) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ParsedUserAgent{}, fmt.Errorf("user-agent is empty")
	}

	out := ParsedUserAgent{}

	switch {
	case strings.Contains(ua, "iPhone"):
		out.Platform = PlatformIOS
		if m := reUAIOSVer.FindStringSubmatch(ua); len(m) > 1 {
			out.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	case strings.Contains(ua, "iPad"):
		out.Platform = PlatformIPadOS
		if m := reUAIOSVer.FindStringSubmatch(ua); len(m) > 1 {
			out.OSVersion = strings.ReplaceAll(m[1], "_", ".")
		}
	case strings.Contains(ua, "Android"):
		out.Platform = PlatformAndroid
		if m := reUAAndroid.FindStringSubmatch(ua); len(m) > 1 {
			out.OSVersion = m[1]
		}
	case strings.Contains(ua, "Windows"):
		out.Platform = PlatformWindows
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		out.Platform = PlatformMac
	case strings.Contains(ua, "X11"), strings.Contains(ua, "Linux"):
		out.Platform = PlatformLinux
	}

	isAppleMobile := out.Platform == PlatformIOS || out.Platform == PlatformIPadOS

	switch {
	case reUAOkhttp.MatchString(ua):
		out.Browser = "okhttp"
		out.Version = reUAOkhttp.FindStringSubmatch(ua)[1]
		if out.Platform == "" {
			out.Platform = PlatformAndroid
		}
	case reUAEdge.MatchString(ua) && uaMajor(reUAEdge.FindStringSubmatch(ua)[1]) >= edgeChromiumFrom:
		out.Browser = "edge"
		out.Version = reUAEdge.FindStringSubmatch(ua)[1]
	case reUABrave.MatchString(ua):
		out.Browser = "brave"
		out.Version = reUABrave.FindStringSubmatch(ua)[1]
	case reUACriOS.MatchString(ua):
		out.Browser = "chrome"
		out.Version = reUACriOS.FindStringSubmatch(ua)[1]
		if out.Platform == "" {
			out.Platform = PlatformIOS
		}
	case reUAFirefox.MatchString(ua) && !isAppleMobile:
		out.Browser = "firefox"
		out.Version = reUAFirefox.FindStringSubmatch(ua)[1]
	case reUAChrome.MatchString(ua):
		out.Browser = "chrome"
		out.Version = reUAChrome.FindStringSubmatch(ua)[1]
	case strings.Contains(ua, "Safari") && reUASafari.MatchString(ua):
		out.Browser = "safari"
		out.Version = reUASafari.FindStringSubmatch(ua)[1]
	case isAppleMobile:
		// An iPhone/iPad UA with no recognizable browser token is an in-app
		// WKWebView: the Google app, Facebook, Instagram, Firefox for iOS, and
		// so on. Apple requires every iOS browser to use WebKit over the system
		// TLS stack, so they all handshake like Safari of the same OS version,
		// which on iOS always matches the Safari version.
		out.Browser = "safari"
		out.Version = out.OSVersion
		if out.Version == "" {
			out.Version = currentSafariVersion
		}
	default:
		return ParsedUserAgent{}, fmt.Errorf("could not identify browser from user-agent: %q", ua)
	}

	if out.Platform == "" {
		// Bots and headless fetchers often ship a UA with no platform token at
		// all (Googlebot's desktop UA, for one). Chromium's ClientHello is
		// identical across desktop platforms, so this only steers the
		// client-hints headers.
		out.Platform = PlatformLinux
	}

	out.Version = clampUAVersion(out.Browser, out.Version)
	return out, nil
}

// currentSafariVersion backs iOS WebView UAs that carry no version anywhere.
const currentSafariVersion = "26.0"

// clampUAVersion raises a browser version up to the oldest one this package can
// model, so a real-world UA for a long-EOL build still yields a usable client
// rather than an error. The nearest supported fingerprint is the closest
// available approximation; NewClientWithPreset stays strict and rejects these
// versions outright, since there the caller chose the version deliberately.
func clampUAVersion(browser, version string) string {
	var floor int
	switch browser {
	case "chrome", "edge", "brave":
		floor = chromiumMinVersion
	case "firefox":
		floor = firefoxMinVersion
	case "safari":
		floor = safariMinVersion
	default:
		return version
	}

	if uaMajor(version) >= floor {
		return version
	}
	return strconv.Itoa(floor) + ".0"
}

// NewClientWithUserAgent creates a Client by parsing the given User-Agent
// string to determine browser, version, platform, and (where applicable) OS
// version. It is a convenience wrapper around NewClientWithPreset.
//
// On success the client sends the exact UA string passed in, and
// Client.Info.UserAgent reports it, rather than the one the preset would
// synthesize. Everything else about the preset still applies, so sec-ch-ua*
// headers are derived from the browser and version inferred from the UA.
//
// Versions older than a preset can model are raised to the oldest supported
// one, since a real-world UA for an EOL build should still produce a usable
// client; see clampUAVersion.
//
// Recognized UA tokens: Chrome, CriOS, Edg/Edge/EdgA/EdgiOS, Brave, Firefox,
// FxiOS, Safari (Version/), and okhttp. An iPhone or iPad UA with no
// recognizable browser token falls back to Safari of the same OS version, and
// a UA with no recognizable platform token falls back to Linux. Returns an
// error if the UA cannot be classified or if the inferred preset is
// unsupported.
func NewClientWithUserAgent(userAgent string, opts ...Option) (*Client, error) {
	parsed, err := ParseUserAgent(userAgent)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: %w", err)
	}

	combined := make([]Option, 0, len(opts)+1)
	if parsed.OSVersion != "" {
		combined = append(combined, WithOSVersion(parsed.OSVersion))
	}
	combined = append(combined, opts...)

	c, err := NewClientWithPreset(parsed.Browser, parsed.Version, string(parsed.Platform), combined...)
	if err != nil {
		return nil, err
	}

	// The preset synthesizes its own user-agent from browser, version, and
	// platform, which rarely matches the input byte for byte: the Android
	// device model, the Windows NT version, and in-app WebView tokens all
	// differ. Requests are what matter, and those take their user-agent from
	// the transport's default headers, so override there too. A nil map means
	// WithoutDefaultHeaders was used and the caller wants no defaults at all.
	if tr, ok := c.httpClient.Transport.(*browserTransport); ok && tr.defaultHeaders != nil {
		tr.defaultHeaders.Set("user-agent", userAgent)
	}

	c.Info.UserAgent = userAgent
	return c, nil
}
