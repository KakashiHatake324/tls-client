package ja3

import (
	"crypto/md5"
	"fmt"
	"testing"

	tls "github.com/refraction-networking/utls"
)

func TestParse(t *testing.T) {
	// Chrome-like JA3
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"

	spec, err := Parse(ja3)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if spec.TLSVersion != 771 {
		t.Errorf("TLSVersion = %d, want 771", spec.TLSVersion)
	}
	if len(spec.CipherSuites) != 15 {
		t.Errorf("CipherSuites count = %d, want 15", len(spec.CipherSuites))
	}
	if spec.CipherSuites[0] != 4865 {
		t.Errorf("CipherSuites[0] = %d, want 4865 (TLS_AES_128_GCM_SHA256)", spec.CipherSuites[0])
	}
	if len(spec.EllipticCurves) != 3 {
		t.Errorf("EllipticCurves count = %d, want 3", len(spec.EllipticCurves))
	}
	if spec.EllipticCurves[0] != tls.X25519 {
		t.Errorf("EllipticCurves[0] = %d, want %d (X25519)", spec.EllipticCurves[0], tls.X25519)
	}
	if len(spec.EllipticCurveFormats) != 1 || spec.EllipticCurveFormats[0] != 0 {
		t.Errorf("EllipticCurveFormats = %v, want [0]", spec.EllipticCurveFormats)
	}
}

func TestClientHelloSpec(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"

	spec, err := Parse(ja3)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	hello := spec.ClientHelloSpec()
	if hello.TLSVersMax != tls.VersionTLS12 {
		t.Errorf("TLSVersMax = 0x%04x, want 0x%04x (TLS 1.2 / JA3 version 771)", hello.TLSVersMax, tls.VersionTLS12)
	}
	if len(hello.CipherSuites) != 15 {
		t.Errorf("CipherSuites count = %d, want 15", len(hello.CipherSuites))
	}
	if len(hello.Extensions) != 15 {
		t.Errorf("Extensions count = %d, want 15", len(hello.Extensions))
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		ja3  string
	}{
		{"too few fields", "771,4865,0"},
		{"bad version", "abc,4865,0,29,0"},
		{"bad cipher", "771,xyz,0,29,0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.ja3)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestEmptyFields(t *testing.T) {
	ja3 := "771,4865,,,"
	spec, err := Parse(ja3)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(spec.Extensions) != 0 {
		t.Errorf("Extensions = %v, want empty", spec.Extensions)
	}
	if len(spec.EllipticCurves) != 0 {
		t.Errorf("EllipticCurves = %v, want empty", spec.EllipticCurves)
	}
}

func TestJA3Hash(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3)))
	if len(hash) != 32 {
		t.Errorf("MD5 hash length = %d, want 32", len(hash))
	}
	t.Logf("JA3 hash: %s", hash)
}

func TestIsGREASE(t *testing.T) {
	greaseVals := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0xfafa}
	for _, v := range greaseVals {
		if !isGREASE(v) {
			t.Errorf("isGREASE(0x%04x) = false, want true", v)
		}
	}
	if isGREASE(0x0001) {
		t.Error("isGREASE(0x0001) = true, want false")
	}
}
