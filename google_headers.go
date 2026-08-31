package tlsclient

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// =====================================================================
// Chrome's Google-only headers: x-client-data and the x-browser-* set
// =====================================================================
//
// Chrome sends a handful of headers that appear on requests to Google-owned
// origins and nowhere else. Sending them to a non-Google host is a giveaway on
// its own, so this package attaches them only to Google-associated hosts over
// HTTPS, mirroring Chrome.
//
// Captured from Chrome 151.0.7922.174 on macOS (2026-08-30) with
// --log-net-log, loading https://www.google.com/:
//
//	x-browser-channel: stable
//	x-browser-year: 2026
//	x-browser-validation: S7hKo5PWMhrUgzQMwm5wWB2agsI=
//	x-browser-copyright: Copyright 2026 Google LLC. All Rights Reserved.
//	x-client-data: CM6XywE=
//
// In that capture they appeared after `accept` and before the `sec-fetch-*`
// group, in the order channel, year, validation, copyright, client-data.

// GoogleHeaders configures the Chrome-only headers attached to Google origins.
// The zero value sends nothing; pass it to WithGoogleHeaders.
type GoogleHeaders struct {
	// ClientData is the verbatim x-client-data value: a base64-encoded
	// ClientVariations protobuf listing the Finch variation IDs this browser
	// is enrolled in. Build one with ClientDataHeader, or paste a value
	// captured from a real Chrome.
	//
	// The value is specific to a browser install and its variations seed —
	// two fresh profiles produced CM6XywE= and CPHsygE= in back-to-back runs —
	// so there is no "correct" value this library can derive for you. Leave it
	// empty to omit the header.
	ClientData string

	// Validation is the verbatim x-browser-validation value. Leave it empty to
	// omit the header, which is the safe default; see BrowserValidation for
	// why this library cannot compute a correct one from scratch.
	Validation string

	// ValidationSecret, when set and Validation is empty, computes the header as
	// base64(sha1(ValidationSecret + userAgent)). The secret is Chrome's
	// kIntegritySeed concatenated with its build API key (see BrowserValidation);
	// both come from a closed Chromium submodule, so this only yields a correct
	// value when you supply a secret extracted from the matching Chrome build.
	ValidationSecret string

	// Channel is x-browser-channel. Defaults to "stable".
	Channel string

	// Year is x-browser-year, and also the year in x-browser-copyright.
	// Defaults to the current year.
	Year string
}

// resolve fills in defaults and computes the derived values for a user agent.
func (g GoogleHeaders) resolve(userAgent string) map[string]string {
	channel := g.Channel
	if channel == "" {
		channel = "stable"
	}
	year := g.Year
	if year == "" {
		year = strconv.Itoa(time.Now().Year())
	}

	validation := g.Validation
	if validation == "" && g.ValidationSecret != "" {
		validation = BrowserValidation(g.ValidationSecret, userAgent)
	}

	out := map[string]string{
		"x-browser-channel":   channel,
		"x-browser-year":      year,
		"x-browser-copyright": fmt.Sprintf("Copyright %s Google LLC. All Rights Reserved.", year),
	}
	if validation != "" {
		out["x-browser-validation"] = validation
	}
	if g.ClientData != "" {
		out["x-client-data"] = g.ClientData
	}
	return out
}

// BrowserValidation computes x-browser-validation as base64(sha1(secret +
// userAgent)). The header was introduced in Chrome 134.
//
// The algorithm is open source. In chrome/common/request_header_integrity/
// request_header_integrity_url_loader_throttle.cc (public chromium/src, behind
// enable_request_header_integrity = is_chrome_branded), AddRequestIntegrityHeaders
// computes:
//
//	base::Base64Encode(base::SHA1Hash(base::as_byte_span(
//	    std::string(kIntegritySeed) + google_apis::GetAPIKey() +
//	    embedder_support::GetUserAgent())))
//
// So the true secret is kIntegritySeed || GOOGLE_API_KEY, a fixed byte string
// per Chrome build. Pass that as the secret argument and this reproduces
// Chrome's value for any User-Agent.
//
// # Why you cannot compute it from scratch
//
// Both halves of the secret live in a CLOSED Chromium submodule
// (src/chrome/common/request_header_integrity/internal and
// src/google_apis/internal), pulled only for official Google builds. The public
// tree defines kIntegritySeed as "" and leaves the API key empty, and an
// unbranded build even compiles the header names as X-Placeholder-1..4 — which
// is why these strings are present in the Google Chrome binary and absent from
// open-source Chromium.
//
// The seed was added around November 2025 (Chromium CL 7104818), before the
// Chrome 151 branch. That is exactly why the older base64(sha1(api_key + ua))
// formula still reproduces Chrome ~134–143 captures but fails on 151: the seed
// used to be empty. With a pinned Windows UA, Chrome 151.0.7922.174 emits
// bvcR2nfcbw0bPYHPJRO+bpzN01M=, which the empty-seed formula does not produce
// under any published key.
//
// SHA-1 is not invertible, so a captured (UA, value) pair does not reveal the
// secret, and one value does not let you compute another for a different UA.
// Unless you extract the secret from the matching Chrome binary, capture the
// real header instead — see the netlog recipe in the README — and pass it as
// GoogleHeaders.Validation. A wrong integrity header is a louder tell than a
// missing one.
func BrowserValidation(secret, userAgent string) string {
	sum := sha1.Sum([]byte(secret + userAgent))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ChromeAPIKey returns the publicly circulated Chrome API key for a platform.
// GetAPIKey() selects the key by BUILD platform, not by the spoofed UA, so a
// macOS Chrome uses the macOS key even while sending a Windows User-Agent.
//
// On current Chrome the key alone is not the validation secret: it is prefixed
// by kIntegritySeed (see BrowserValidation), so these keys reproduce only
// pre-seed captures (Chrome ~134–143). They are kept for that case and as the
// key half of a full secret you may recover.
func ChromeAPIKey(p Platform) string {
	switch p {
	case PlatformWindows:
		return "AIzaSyA2KlwBX3mkFo30om9LUFYQhpqLoa_BNhE"
	case PlatformLinux, PlatformAndroid:
		return "AIzaSyBqJZh-7pA44blAaAkH6490hUFOwX0KCYM"
	case PlatformMac, PlatformIOS, PlatformIPadOS:
		return "AIzaSyDr2UxVnv_U85AbhhY8XSHSIavUW0DC-sY"
	default:
		return ""
	}
}

// ClientDataHeader encodes an x-client-data value: the ClientVariations
// protobuf from components/variations/proto/client_variations.proto, base64
// encoded. Field 1 carries the variation IDs Chrome reports for analysis, and
// field 3 the ones that trigger server-side behavior.
//
// IDs are sorted and de-duplicated, matching the set Chrome serializes from.
// Verified against real captures: ClientDataHeader([]int32{3328974}, nil)
// returns "CM6XywE=", the value a fresh Chrome 151 profile sent to google.com.
//
// Real values change with the variations seed, so the useful sources are a
// capture from the browser you are imitating or a set of IDs you already know.
func ClientDataHeader(variationIDs, triggerVariationIDs []int32) string {
	var buf []byte
	buf = appendVariationIDs(buf, 1, variationIDs)
	buf = appendVariationIDs(buf, 3, triggerVariationIDs)
	if len(buf) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// appendVariationIDs writes a repeated varint field in protobuf wire format.
func appendVariationIDs(dst []byte, field int, ids []int32) []byte {
	if len(ids) == 0 {
		return dst
	}
	sorted := append([]int32(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	tag := byte(field<<3) | 0 // wire type 0: varint
	var prev int32
	for i, id := range sorted {
		if i > 0 && id == prev {
			continue
		}
		prev = id
		dst = append(dst, tag)
		dst = appendVarint(dst, uint64(uint32(id)))
	}
	return dst
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// googleHostSuffixes are hosts whose traffic carries Chrome's Google-only
// headers, beyond the google.<TLD> and youtube.<TLD> patterns handled
// separately. The first five come from Chromium's IsGoogleAssociatedDomainUrl;
// the rest were observed receiving the headers in the Chrome 151 capture.
var googleHostSuffixes = []string{
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"googleusercontent.com",
	"googleapis.com",
	"gstatic.com",
	"ggpht.com",
	"youtu.be",
}

// IsGoogleAssociatedHost reports whether Chrome would treat host as a Google
// property for the purposes of x-client-data and the x-browser-* headers.
// The host may include a port.
func IsGoogleAssociatedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return false
	}

	for _, suffix := range googleHostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return hasRegistrableLabel(host, "google") || hasRegistrableLabel(host, "youtube")
}

// hasRegistrableLabel reports whether host is label.<TLD> or *.label.<TLD>,
// covering both google.com and multi-part suffixes such as google.co.uk.
//
// A public suffix list would be exact; this approximation accepts a trailing
// run of one or two short labels, which is what Google's country domains look
// like, and rejects things like google.evil.com.
func hasRegistrableLabel(host, label string) bool {
	parts := strings.Split(host, ".")
	for i, p := range parts {
		if p != label {
			continue
		}
		rest := parts[i+1:]
		switch len(rest) {
		case 1:
			if len(rest[0]) >= 2 {
				return true
			}
		case 2:
			// e.g. google.co.uk, google.com.au
			if len(rest[0]) <= 3 && len(rest[1]) >= 2 {
				return true
			}
		}
	}
	return false
}
