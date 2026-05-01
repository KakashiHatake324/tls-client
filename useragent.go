package tlsclient

import (
	"fmt"
	"regexp"
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
	reUAIOSVer  = regexp.MustCompile(`(?:iPhone OS|CPU OS) (\d+[_\.]\d+(?:[_\.]\d+)?)`)
)

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

	switch {
	case reUAOkhttp.MatchString(ua):
		out.Browser = "okhttp"
		out.Version = reUAOkhttp.FindStringSubmatch(ua)[1]
		if out.Platform == "" {
			out.Platform = PlatformAndroid
		}
	case reUAEdge.MatchString(ua):
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
	case reUAFirefox.MatchString(ua):
		out.Browser = "firefox"
		out.Version = reUAFirefox.FindStringSubmatch(ua)[1]
	case reUAChrome.MatchString(ua):
		out.Browser = "chrome"
		out.Version = reUAChrome.FindStringSubmatch(ua)[1]
	case strings.Contains(ua, "Safari") && reUASafari.MatchString(ua):
		out.Browser = "safari"
		out.Version = reUASafari.FindStringSubmatch(ua)[1]
	default:
		return ParsedUserAgent{}, fmt.Errorf("could not identify browser from user-agent: %q", ua)
	}

	if out.Platform == "" {
		return ParsedUserAgent{}, fmt.Errorf("could not identify platform from user-agent: %q", ua)
	}

	return out, nil
}

// NewClientWithUserAgent creates a Client by parsing the given User-Agent
// string to determine browser, version, platform, and (where applicable) OS
// version. It is a convenience wrapper around NewClientWithPreset.
//
// On success, Client.Info.UserAgent is set to the exact UA string passed in,
// so GetDefaultUserAgent round-trips the user's value rather than the one
// synthesized by the preset.
//
// Recognized UA tokens: Chrome, CriOS, Edg/Edge/EdgA/EdgiOS, Brave, Firefox,
// FxiOS, Safari (Version/), and okhttp. Returns an error if the UA cannot be
// classified or if the inferred preset is unsupported.
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

	c.Info.UserAgent = userAgent
	return c, nil
}
