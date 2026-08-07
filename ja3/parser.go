package ja3

import (
	"fmt"
	"strconv"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// Spec holds a parsed JA3 string and can produce a utls.ClientHelloSpec.
type Spec struct {
	TLSVersion           uint16
	CipherSuites         []uint16
	Extensions           []uint16
	EllipticCurves       []tls.CurveID
	EllipticCurveFormats []uint8
}

// Parse splits a JA3 string (TLSVersion,Ciphers,Extensions,Curves,CurveFormats)
// into its component numeric fields.
func Parse(ja3 string) (*Spec, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("ja3: expected 5 comma-separated fields, got %d", len(parts))
	}

	ver, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("ja3: invalid TLS version %q: %w", parts[0], err)
	}

	ciphers, err := parseUint16List(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ja3: ciphers: %w", err)
	}

	extensions, err := parseUint16List(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ja3: extensions: %w", err)
	}

	curves, err := parseUint16List(parts[3])
	if err != nil {
		return nil, fmt.Errorf("ja3: curves: %w", err)
	}

	formats, err := parseUint8List(parts[4])
	if err != nil {
		return nil, fmt.Errorf("ja3: point formats: %w", err)
	}

	curveIDs := make([]tls.CurveID, len(curves))
	for i, c := range curves {
		curveIDs[i] = tls.CurveID(c)
	}

	return &Spec{
		TLSVersion:           uint16(ver),
		CipherSuites:         ciphers,
		Extensions:           extensions,
		EllipticCurves:       curveIDs,
		EllipticCurveFormats: formats,
	}, nil
}

// ClientHelloSpec converts the parsed JA3 into a utls.ClientHelloSpec that can
// be applied to a UConn via ApplyPreset.
func (s *Spec) ClientHelloSpec() *tls.ClientHelloSpec {
	var extensions []tls.TLSExtension
	for _, extID := range s.Extensions {
		extensions = append(extensions, mapExtension(extID, s))
	}

	return &tls.ClientHelloSpec{
		TLSVersMax:   s.MaxVersion(),
		TLSVersMin:   tls.VersionTLS10,
		CipherSuites: s.CipherSuites,
		Extensions:   extensions,
	}
}

// MaxVersion returns the highest TLS version the spec should offer.
//
// The first JA3 field is the ClientHello legacy_version, which RFC 8446 pins to
// 0x0303 (771) for every TLS 1.3 client so middleboxes keep working; 1.3 is
// negotiated through the supported_versions extension instead. Taking that
// field literally would cap the handshake at TLS 1.2 and produce a "t12d" JA4
// where a real browser produces "t13d", so infer 1.3 support from the presence
// of a TLS 1.3-only cipher suite (0x13xx), which is only usable under 1.3.
func (s *Spec) MaxVersion() uint16 {
	for _, cs := range s.CipherSuites {
		if cs>>8 == 0x13 {
			return tls.VersionTLS13
		}
	}
	return s.TLSVersion
}

// ToClientHelloSpec is a convenience that parses a JA3 string and returns a
// ready-to-use ClientHelloSpec in one step.
func ToClientHelloSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	spec, err := Parse(ja3)
	if err != nil {
		return nil, err
	}
	return spec.ClientHelloSpec(), nil
}

// mapExtension returns a concrete TLS extension implementation for known
// extension IDs, populating data from the JA3 spec where applicable.
// Unknown extensions are emitted as empty GenericExtensions (id-only stubs).
func mapExtension(id uint16, s *Spec) tls.TLSExtension {
	switch id {
	case 0: // server_name — filled at connection time by utls
		return &tls.SNIExtension{}
	case 5: // status_request (OCSP stapling)
		return &tls.StatusRequestExtension{}
	case 10: // supported_groups
		return &tls.SupportedCurvesExtension{Curves: s.EllipticCurves}
	case 11: // ec_point_formats
		return &tls.SupportedPointsExtension{SupportedPoints: s.EllipticCurveFormats}
	case 13: // signature_algorithms
		return &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: defaultSignatureAlgorithms(),
		}
	case 16: // ALPN
		return &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	case 17: // status_request_v2
		return &tls.StatusRequestV2Extension{}
	case 18: // signed_certificate_timestamp
		return &tls.SCTExtension{}
	case 21: // padding
		return &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
	case 22: // encrypt_then_mac
		return &tls.GenericExtension{Id: 22}
	case 23: // extended_master_secret
		return &tls.ExtendedMasterSecretExtension{}
	case 27: // compress_certificate
		return &tls.UtlsCompressCertExtension{
			Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		}
	case 28: // record_size_limit
		return &tls.FakeRecordSizeLimitExtension{Limit: 0x4001}
	case 34: // delegated_credentials (used by Firefox)
		return &tls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
		}
	case 35: // session_ticket
		return &tls.SessionTicketExtension{}
	case 43: // supported_versions
		return supportedVersionsExt(s.MaxVersion())
	case 44: // cookie
		return &tls.CookieExtension{}
	case 45: // psk_key_exchange_modes
		return &tls.PSKKeyExchangeModesExtension{
			Modes: []uint8{tls.PskModeDHE},
		}
	case 49: // post_handshake_auth
		return &tls.GenericExtension{Id: 49}
	case 50: // signature_algorithms_cert
		return &tls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: defaultSignatureAlgorithms(),
		}
	case 51: // key_share
		return keyShareFromCurves(s.EllipticCurves)
	case 57: // quic_transport_parameters
		return &tls.QUICTransportParametersExtension{}
	case 51764: // trust_anchors (0xca34), Chrome 141+ behind a Finch trial.
		// A JA3 string carries only extension IDs, so send the empty
		// RequestedTrustAnchorList that Chrome uses on an initial connection:
		// a 16-bit length prefix of zero.
		return &tls.GenericExtension{Id: 51764, Data: []byte{0x00, 0x00}}
	case 17613: // application_settings (ALPS, new codepoint used by Chrome 107+)
		return &tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}
	case 17513: // application_settings (ALPS, old codepoint)
		return &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
	case 65037: // encrypted_client_hello (ECH, BoringSSL GREASE)
		return tls.BoringGREASEECH()
	case 65281: // renegotiation_info
		return &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}
	default:
		if isGREASE(id) {
			return &tls.UtlsGREASEExtension{}
		}
		return &tls.GenericExtension{Id: id}
	}
}

func keyShareFromCurves(curves []tls.CurveID) *tls.KeyShareExtension {
	var shares []tls.KeyShare
	for _, c := range curves {
		switch c {
		case tls.X25519MLKEM768, tls.X25519, tls.CurveP256:
			shares = append(shares, tls.KeyShare{Group: c})
		}
		if len(shares) >= 2 {
			break
		}
	}
	if len(shares) == 0 {
		shares = []tls.KeyShare{{Group: tls.X25519}}
	}
	return &tls.KeyShareExtension{KeyShares: shares}
}

func supportedVersionsExt(maxVer uint16) *tls.SupportedVersionsExtension {
	// Real TLS 1.3 clients advertise only 1.3 and 1.2 here. Appending 1.1/1.0
	// would not match any browser and would change the peetprint, whose first
	// field is this exact list.
	if maxVer >= tls.VersionTLS13 {
		return &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		}}
	}
	versions := []uint16{maxVer}
	if maxVer >= tls.VersionTLS12 {
		versions = append(versions, tls.VersionTLS11, tls.VersionTLS10)
	}
	return &tls.SupportedVersionsExtension{Versions: versions}
}

func defaultSignatureAlgorithms() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.PSSWithSHA256,
		tls.PKCS1WithSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.PSSWithSHA384,
		tls.PKCS1WithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA512,
	}
}

// isGREASE returns true for GREASE values (0x0a0a, 0x1a1a, ... 0xfafa).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func parseUint16List(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	tokens := strings.Split(s, "-")
	out := make([]uint16, 0, len(tokens))
	for _, t := range tokens {
		v, err := strconv.ParseUint(strings.TrimSpace(t), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid uint16 %q: %w", t, err)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func parseUint8List(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	tokens := strings.Split(s, "-")
	out := make([]uint8, 0, len(tokens))
	for _, t := range tokens {
		v, err := strconv.ParseUint(strings.TrimSpace(t), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid uint8 %q: %w", t, err)
		}
		out = append(out, uint8(v))
	}
	return out, nil
}
