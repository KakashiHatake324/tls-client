package tlsclient

import (
	"bytes"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestEncodeTrustAnchorIDDraftVector checks the worked example from
// draft-ietf-tls-trust-anchor-ids section 3: the ID "32473.1" has the binary
// representation {0x81, 0xfd, 0x59, 0x01}.
func TestEncodeTrustAnchorIDDraftVector(t *testing.T) {
	got, err := encodeTrustAnchorID("32473.1")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{0x81, 0xfd, 0x59, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeTrustAnchorID(\"32473.1\") = % x, want % x", got, want)
	}
}

func TestEncodeTrustAnchorID(t *testing.T) {
	cases := []struct {
		id   string
		want []byte
	}{
		{"1", []byte{0x01}},
		{"0", []byte{0x00}},
		{"127", []byte{0x7f}},
		{"128", []byte{0x81, 0x00}},
		{"255", []byte{0x81, 0x7f}},
		{"16384", []byte{0x81, 0x80, 0x00}},
		{"1.2.3", []byte{0x01, 0x02, 0x03}},
		{"32473.2.1", []byte{0x81, 0xfd, 0x59, 0x02, 0x01}},
	}
	for _, tc := range cases {
		got, err := encodeTrustAnchorID(tc.id)
		if err != nil {
			t.Errorf("%s: unexpected error %v", tc.id, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s = % x, want % x", tc.id, got, tc.want)
		}
	}
}

func TestEncodeTrustAnchorIDErrors(t *testing.T) {
	for _, id := range []string{"", "   ", "abc", "1.b", "-1", "1..2", "1.2."} {
		if _, err := encodeTrustAnchorID(id); err == nil {
			t.Errorf("expected error for %q, got nil", id)
		}
	}
}

func TestBuildTrustAnchorsExtension(t *testing.T) {
	// Empty list: extension_data is just a zero 16-bit length prefix.
	ext, err := buildTrustAnchorsExtension(nil)
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if ext.Id != 0xca34 {
		t.Errorf("id = %#x, want 0xca34", ext.Id)
	}
	if want := []byte{0x00, 0x00}; !bytes.Equal(ext.Data, want) {
		t.Errorf("empty data = % x, want % x", ext.Data, want)
	}

	// One ID: 2-byte list length, then 1-byte ID length, then the ID.
	ext, err = buildTrustAnchorsExtension([]string{"32473.1"})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	want := []byte{0x00, 0x05, 0x04, 0x81, 0xfd, 0x59, 0x01}
	if !bytes.Equal(ext.Data, want) {
		t.Errorf("single data = % x, want % x", ext.Data, want)
	}

	// Two IDs concatenate, each with its own length prefix.
	ext, err = buildTrustAnchorsExtension([]string{"32473.1", "1.2"})
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	want = []byte{0x00, 0x08, 0x04, 0x81, 0xfd, 0x59, 0x01, 0x02, 0x01, 0x02}
	if !bytes.Equal(ext.Data, want) {
		t.Errorf("multi data = % x, want % x", ext.Data, want)
	}
}

// TestTrustAnchorsExtensionWireFormat verifies the full on-the-wire bytes,
// including the extension type and length that GenericExtension writes.
func TestTrustAnchorsExtensionWireFormat(t *testing.T) {
	ext, err := buildTrustAnchorsExtension(nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	buf := make([]byte, ext.Len())
	if _, err := ext.Read(buf); err != nil && err.Error() != "EOF" {
		t.Fatalf("read: %v", err)
	}
	// ca34 (type) 0002 (length) 0000 (empty list)
	want := []byte{0xca, 0x34, 0x00, 0x02, 0x00, 0x00}
	if !bytes.Equal(buf, want) {
		t.Errorf("wire = % x, want % x", buf, want)
	}
}

func TestMLDSASignatureAlgorithms(t *testing.T) {
	classical := []utls.SignatureScheme{
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
	}

	if got := (chromeExperiments{}).signatureAlgorithms(classical); len(got) != 2 {
		t.Errorf("without WithMLDSA: got %d algorithms, want 2", len(got))
	}

	got := chromeExperiments{mldsa: true}.signatureAlgorithms(classical)
	want := []utls.SignatureScheme{
		0x0904, 0x0905, 0x0906,
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d algorithms, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("algorithm[%d] = %#04x, want %#04x", i, got[i], want[i])
		}
	}
}

// TestChromeSpecExtensionCount confirms the experiments add exactly one
// extension and that GREASE stays pinned to the end of the shuffled list.
func TestChromeSpecExtensionCount(t *testing.T) {
	base, err := chrome133TLSSpec(chromeExperiments{})
	if err != nil {
		t.Fatalf("base spec: %v", err)
	}
	withTA, err := chrome133TLSSpec(chromeExperiments{trustAnchorsSet: true})
	if err != nil {
		t.Fatalf("trust anchors spec: %v", err)
	}

	if len(withTA.Extensions) != len(base.Extensions)+1 {
		t.Errorf("with trust_anchors: %d extensions, want %d",
			len(withTA.Extensions), len(base.Extensions)+1)
	}

	for name, spec := range map[string]*utls.ClientHelloSpec{"base": base, "trust_anchors": withTA} {
		last := spec.Extensions[len(spec.Extensions)-1]
		if _, ok := last.(*utls.UtlsGREASEExtension); !ok {
			t.Errorf("%s: last extension is %T, want *utls.UtlsGREASEExtension", name, last)
		}
	}
}

func TestWithTrustAnchorsInvalidID(t *testing.T) {
	_, err := NewClientWithPreset("chrome", "151.0.0.0", "mac", WithTrustAnchors("not-an-oid"))
	if err == nil {
		t.Fatal("expected error for malformed trust anchor ID, got nil")
	}
}

func TestExperimentsRejectedOnOldChrome(t *testing.T) {
	if _, err := NewClientWithPreset("chrome", "120.0.0.0", "mac", WithTrustAnchors()); err == nil {
		t.Error("expected error using WithTrustAnchors on Chrome 120, got nil")
	}
	if _, err := NewClientWithPreset("chrome", "120.0.0.0", "mac", WithMLDSA()); err == nil {
		t.Error("expected error using WithMLDSA on Chrome 120, got nil")
	}
}

func TestExperimentsOptInOnly(t *testing.T) {
	c, err := NewClientWithPreset("chrome", "151.0.0.0", "mac")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if c.experiments.any() {
		t.Error("experiments should be off unless explicitly enabled")
	}
}
