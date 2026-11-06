package tlsclient

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// extensionTrustAnchors is the TLS trust_anchors extension code point from
// draft-ietf-tls-trust-anchor-ids (BoringSSL: TLSEXT_TYPE_trust_anchors).
const extensionTrustAnchors uint16 = 0xca34

// extensionServerPadding is BoringSSL's TLSEXT_TYPE_server_padding (4832), the
// two-byte padding request Chrome sends while the AddTLSServerHandshakePadding
// field trial is on. See chromiumServerPaddingFrom in profiles.go.
const extensionServerPadding uint16 = 0x12e0

// ML-DSA signature schemes from draft-ietf-tls-mldsa. Chrome advertises these
// ahead of the classical algorithms. uTLS 1.8.2 has no named constants for them.
const (
	sigMLDSA44 utls.SignatureScheme = 0x0904
	sigMLDSA65 utls.SignatureScheme = 0x0905
	sigMLDSA87 utls.SignatureScheme = 0x0906
)

// chromeMLDSAFrom is the first Chrome major version that advertises the ML-DSA
// signature schemes by default, ahead of the classical algorithms.
//
// Chrome 150 turned this on for stable across Android, ChromeOS, Linux, macOS,
// Windows, and Fuchsia ("Support for ML-DSA in TLS enabled by default", Chrome
// Enterprise release notes). The advertisement is unconditional: Chrome offers
// the schemes in every ClientHello even though an ML-DSA certificate can only
// be used when a trusted ML-DSA root is configured manually.
//
// Verified against a live capture of Chrome 151.0.7922.174 on macOS (headed and
// headless, 2026-08-30), whose signature_algorithms list is
// 2308-2309-2310-1027-2052-1025-1283-2053-1281-2054-1537.
//
// This changes JA4_c and the peetprint but NOT JA3 or JA3N, which do not encode
// signature algorithms at all — which is exactly why a JA3N-only check keeps
// passing while the client no longer matches Chrome.
const chromeMLDSAFrom = 150

// chromeTrustAnchorsFrom is the first Chrome major version that sends the
// trust_anchors extension (0xca34) on every ClientHello, carrying the Chrome
// Root Store trust anchor IDs rather than an empty list.
//
// Through Chrome 151 this was gated behind the TLSTrustAnchorIDs Finch trial and
// off for stable. Chrome 152 turned it on unconditionally: a capture of
// 152.0.7977.65 (macOS, fresh profile, 2026-08-31) carries a 210-byte extension
// with the 32 IDs in chromeRootStoreTrustAnchorIDs. That takes the extension
// count from 16 to 17 and moves JA3N and the JA4 prefix.
const chromeTrustAnchorsFrom = 152

// chromeGreaseSigAlgsFrom is the first Chrome major version that prepends a
// GREASE value to signature_algorithms, alongside the GREASE it already places
// in ciphers, extensions, groups, key shares, and supported_versions.
//
// Also new in Chrome 152: the same capture shows a fresh GREASE codepoint per
// connection (0x6a6a then 0x2a2a on consecutive hellos) ahead of the ML-DSA
// entries, making the list 12 long. JA4 ignores GREASE, so JA4_c is unaffected
// for implementations that follow the spec.
const chromeGreaseSigAlgsFrom = 152

// chromeTrustAnchorList153From is the first Chrome major whose compiled-in
// Chrome Root Store carries the 28-ID trust anchor list rather than the 32-ID
// one. net/data/ssl/chrome_root_store/root_store.textproto has 32
// trust_anchor_id fields at 152.0.7977.85 (version_major 36) and 28 at
// 153.0.8010.12 (version_major 38) through 157.0.8103.38 (version_major 42):
// the Google Trust Services IDs 11129.9.2, .3, .9, and .14 are gone and nothing
// was added. The 28-ID list is confirmed on the wire by a real headed Chrome
// 156.0.8078.x and a fresh Chrome 157.0.8103.38 (both 2026-11-06), which sent
// the identical 186-byte body pinned in TestChromeTrustAnchorIDsMatchCapture.
//
// The root store also ships through the component updater, so a long-running
// older Chrome may have moved to the newer list; the version default here
// follows the store compiled into each release.
const chromeTrustAnchorList153From = 153

// chromeRootStoreTrustAnchorIDs152 is the trust anchor ID list Chrome 152
// sends, decoded from a live capture. The IDs are dotted-decimal relative OIDs:
// 11129.9.x is Google Trust Services, 44947.2.x is ISRG (Let's Encrypt), and
// 52580.200109.1.x is a third CA family.
//
// Chrome 152 iterated a hash set to build this, so the order differed between
// browser processes while the set did not. The order below is one real
// capture's; since neither JA3 nor JA4 covers extension bodies, it affects only
// the raw bytes.
var chromeRootStoreTrustAnchorIDs152 = []string{
	"11129.9.6", "52580.200109.1.7", "11129.9.12", "44947.2.6",
	"44947.2.19", "52580.200109.1.13", "11129.9.1", "44947.2.13",
	"11129.9.13", "44947.2.15", "52580.200109.1.8", "44947.2.18",
	"52580.200109.1.9", "11129.9.2", "44947.2.1", "11129.9.14",
	"11129.9.9", "52580.200109.1.10", "11129.9.3", "11129.9.15",
	"52580.200109.1.11", "11129.9.4", "44947.2.20", "11129.9.10",
	"52580.200109.1.19", "52580.200109.1.18", "11129.9.7", "11129.9.8",
	"52580.200109.1.12", "11129.9.5", "44947.2.14", "11129.9.11",
}

// chromeRootStoreTrustAnchorIDs153 is the list Chrome 153 and up send: the 152
// set minus 11129.9.2, .3, .9, and .14. Unlike 152, the order is stable: it was
// byte-identical across five launches of three builds (Chrome 156 headed, Chrome
// for Testing 156 twice, Chrome 157 twice) and is sorted by the binary encoding
// of each ID, so it is reproduced verbatim.
var chromeRootStoreTrustAnchorIDs153 = []string{
	"44947.2.1", "44947.2.6", "44947.2.13", "44947.2.14",
	"44947.2.15", "44947.2.18", "44947.2.19", "44947.2.20",
	"52580.200109.1.7", "52580.200109.1.8", "52580.200109.1.9", "52580.200109.1.10",
	"52580.200109.1.11", "52580.200109.1.12", "52580.200109.1.13", "52580.200109.1.18",
	"52580.200109.1.19", "11129.9.1", "11129.9.4", "11129.9.5",
	"11129.9.6", "11129.9.7", "11129.9.8", "11129.9.10",
	"11129.9.11", "11129.9.12", "11129.9.13", "11129.9.15",
}

// chromeRootStoreTrustAnchorIDs returns the list the Chrome Root Store compiled
// into a given major advertises.
func chromeRootStoreTrustAnchorIDs(majorNum int) []string {
	if majorNum >= chromeTrustAnchorList153From {
		return chromeRootStoreTrustAnchorIDs153
	}
	return chromeRootStoreTrustAnchorIDs152
}

// chromeExperiments holds ClientHello features whose presence depends on the
// Chrome version or on a Finch field trial, together with any caller override.
type chromeExperiments struct {
	trustAnchors     []string
	trustAnchorsSet  bool
	trustAnchorsOff  bool
	mldsa            bool
	mldsaSet         bool
	serverPadding    uint16
	serverPaddingSet bool
	serverPaddingOff bool
}

func (e chromeExperiments) any() bool {
	return e.trustAnchorsSet || e.trustAnchorsOff || e.mldsaSet ||
		e.serverPaddingSet || e.serverPaddingOff
}

// usesTrustAnchors reports whether a Chrome build of this major version sends
// the trust_anchors extension, honouring an explicit override.
func (e chromeExperiments) usesTrustAnchors(majorNum int) bool {
	if e.trustAnchorsOff {
		return false
	}
	if e.trustAnchorsSet {
		return true
	}
	return majorNum >= chromeTrustAnchorsFrom
}

// trustAnchorIDs returns the IDs to advertise: the caller's list when one was
// given, otherwise the Chrome Root Store set compiled into that Chrome major.
func (e chromeExperiments) trustAnchorIDs(majorNum int) []string {
	if e.trustAnchorsSet {
		return e.trustAnchors
	}
	return chromeRootStoreTrustAnchorIDs(majorNum)
}

// usesMLDSA reports whether a Chrome build of this major version advertises the
// ML-DSA schemes. An explicit WithMLDSA/WithoutMLDSA overrides the version
// default, which is what a caller reproducing a pre-150 capture wants.
func (e chromeExperiments) usesMLDSA(majorNum int) bool {
	if e.mldsaSet {
		return e.mldsa
	}
	return majorNum >= chromeMLDSAFrom
}

// signatureAlgorithms returns the signature_algorithms list for a Chromium
// spec: a GREASE placeholder for the versions that lead with one, then the
// ML-DSA schemes for the versions that send them, then the classical set.
func (e chromeExperiments) signatureAlgorithms(majorNum int, classical []utls.SignatureScheme) []utls.SignatureScheme {
	grease := majorNum >= chromeGreaseSigAlgsFrom
	mldsa := e.usesMLDSA(majorNum)
	if !grease && !mldsa {
		return classical
	}

	out := make([]utls.SignatureScheme, 0, len(classical)+4)
	if grease {
		out = append(out, utls.SignatureScheme(randomGREASEValue()))
	}
	if mldsa {
		out = append(out, sigMLDSA44, sigMLDSA65, sigMLDSA87)
	}
	return append(out, classical...)
}

// randomGREASEValue returns one of the 16 GREASE codepoints from RFC 8701.
//
// uTLS substitutes its GREASE_PLACEHOLDER for cipher suites, extensions,
// supported_groups, key_share, and supported_versions, but has no case for
// signature_algorithms, so a placeholder left there would go out on the wire
// verbatim as 0x0a0a on every connection. Real Chrome derives a fresh value per
// connection (0x6a6a and 0x2a2a on consecutive hellos in the 152 capture), and
// the spec function runs per connection, so picking here reproduces that.
func randomGREASEValue() uint16 {
	v := uint16(rand.IntN(16)) << 4
	return v<<8 | v | 0x0a0a
}

// trustAnchorsExtension builds the trust_anchors extension for a Chrome major
// version, or returns nil when that version does not send one.
func (e chromeExperiments) trustAnchorsExtension(majorNum int) (utls.TLSExtension, error) {
	if !e.usesTrustAnchors(majorNum) {
		return nil, nil
	}
	return buildTrustAnchorsExtension(e.trustAnchorIDs(majorNum))
}

// serverPaddingExtension builds the server_padding extension for a Chrome major
// version, or returns nil when that version does not send one. An explicit
// WithServerPadding/WithoutServerPadding overrides the version default, which is
// on for 153 alone; see chromiumServerPaddingFrom.
func (e chromeExperiments) serverPaddingExtension(majorNum int) utls.TLSExtension {
	switch {
	case e.serverPaddingOff:
		return nil
	case e.serverPaddingSet:
		return buildServerPaddingExtension(e.serverPadding)
	case majorNum >= chromiumServerPaddingFrom && majorNum < chromiumServerPaddingUntil:
		return buildServerPaddingExtension(chromeServerPaddingBytes153)
	default:
		return nil
	}
}

// buildServerPaddingExtension encodes a server_padding request: the number of
// padding bytes as a 16-bit big-endian integer, exactly as BoringSSL's
// ext_server_padding_add_clienthello writes it.
func buildServerPaddingExtension(n uint16) *utls.GenericExtension {
	return &utls.GenericExtension{
		Id:   extensionServerPadding,
		Data: []byte{byte(n >> 8), byte(n)},
	}
}

// buildTrustAnchorsExtension encodes a RequestedTrustAnchorList for the
// ClientHello. Per draft-ietf-tls-trust-anchor-ids section 4.1 the
// extension_data is a 16-bit length-prefixed list of TrustAnchorIDs, each of
// which is itself 8-bit length-prefixed. The list may be empty, which is what
// Chrome sends on an initial connection when it has no server-advertised IDs
// to intersect against.
func buildTrustAnchorsExtension(ids []string) (*utls.GenericExtension, error) {
	var list []byte
	for _, id := range ids {
		encoded, err := encodeTrustAnchorID(id)
		if err != nil {
			return nil, err
		}
		list = append(list, byte(len(encoded)))
		list = append(list, encoded...)
	}
	if len(list) > 0xffff {
		return nil, fmt.Errorf("trust anchor list is %d bytes, exceeds the 65535-byte limit", len(list))
	}

	data := make([]byte, 2, 2+len(list))
	data[0] = byte(len(list) >> 8)
	data[1] = byte(len(list))
	data = append(data, list...)

	return &utls.GenericExtension{Id: extensionTrustAnchors, Data: data}, nil
}

// encodeTrustAnchorID converts a trust anchor ID from its ASCII representation
// (dotted decimal relative OID, e.g. "32473.1") into the binary representation
// used on the wire: the contents octets of the relative OID's DER encoding,
// i.e. each arc as a base-128 varint with the continuation bit set on all but
// the final byte. The tag and length octets are omitted.
//
// Example from the draft: "32473.1" encodes to {0x81, 0xfd, 0x59, 0x01}.
func encodeTrustAnchorID(id string) ([]byte, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("trust anchor ID is empty")
	}

	var out []byte
	for _, arc := range strings.Split(id, ".") {
		n, err := strconv.ParseUint(arc, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid trust anchor ID %q: arc %q is not a non-negative integer", id, arc)
		}
		out = append(out, appendBase128(nil, n)...)
	}

	// The draft caps the binary representation at 255 bytes so it fits the
	// 8-bit length prefix.
	if len(out) > 255 {
		return nil, fmt.Errorf("trust anchor ID %q encodes to %d bytes, exceeds the 255-byte limit", id, len(out))
	}
	return out, nil
}

// appendBase128 appends v to dst as a base-128 big-endian varint, setting the
// high bit on every byte except the last.
func appendBase128(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, 0x00)
	}

	var groups []byte
	for v > 0 {
		groups = append(groups, byte(v&0x7f))
		v >>= 7
	}
	for i := len(groups) - 1; i >= 0; i-- {
		b := groups[i]
		if i > 0 {
			b |= 0x80
		}
		dst = append(dst, b)
	}
	return dst
}
