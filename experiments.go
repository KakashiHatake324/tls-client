package tlsclient

import (
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// extensionTrustAnchors is the TLS trust_anchors extension code point from
// draft-ietf-tls-trust-anchor-ids (BoringSSL: TLSEXT_TYPE_trust_anchors).
const extensionTrustAnchors uint16 = 0xca34

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

// chromeExperiments holds ClientHello features whose presence depends on the
// Chrome version or on a Finch field trial, together with any caller override.
type chromeExperiments struct {
	trustAnchors    []string
	trustAnchorsSet bool
	mldsa           bool
	mldsaSet        bool
}

func (e chromeExperiments) any() bool {
	return e.trustAnchorsSet || e.mldsaSet
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
// spec, prepending the ML-DSA schemes for the versions that send them.
func (e chromeExperiments) signatureAlgorithms(majorNum int, classical []utls.SignatureScheme) []utls.SignatureScheme {
	if !e.usesMLDSA(majorNum) {
		return classical
	}
	out := make([]utls.SignatureScheme, 0, len(classical)+3)
	out = append(out, sigMLDSA44, sigMLDSA65, sigMLDSA87)
	return append(out, classical...)
}

// trustAnchorsExtension builds the trust_anchors extension, or returns nil if
// the experiment is not enabled.
func (e chromeExperiments) trustAnchorsExtension() (utls.TLSExtension, error) {
	if !e.trustAnchorsSet {
		return nil, nil
	}
	return buildTrustAnchorsExtension(e.trustAnchors)
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
