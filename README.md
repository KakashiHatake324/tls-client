# tls-client

A Go module for making HTTP requests with custom TLS fingerprints. Mimic any browser or device by using built-in presets or providing a JA3 fingerprint string.

Built on [uTLS](https://github.com/refraction-networking/utls) for low-level ClientHello control.

## Install

```bash
go get github.com/KakashiHatake324/tls-client
```

Requires Go 1.21+.

## Quick Start

### Browser Preset

```go
package main

import (
    "fmt"
    "io"
    "log"

    tlsclient "github.com/KakashiHatake324/tls-client"
)

func main() {
    client, err := tlsclient.NewClientWithPreset("chrome")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Get("https://tls.peet.ws/api/all")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### Custom JA3 String

Pass any JA3 fingerprint string to reproduce that exact TLS ClientHello:

```go
// Chrome 145 JA3 (captured from a real browser)
ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0"

client, err := tlsclient.NewClientWithJA3(ja3)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

resp, err := client.Get("https://example.com")
```

The server will see exactly the cipher suites, extensions, and curves encoded in the JA3 string.

### With Proxy

```go
client, err := tlsclient.NewClientWithPreset("chrome",
    tlsclient.WithProxy("socks5://user:pass@127.0.0.1:1080"),
)
```

Supported proxy schemes: `http`, `https`, `socks5`, `socks5h`.

### With Options

```go
client, err := tlsclient.NewClientWithJA3(ja3,
    tlsclient.WithTimeout(15 * time.Second),
    tlsclient.WithDialTimeout(5 * time.Second),
    tlsclient.WithProxy("http://proxy.example.com:8080"),
    tlsclient.WithInsecureSkipVerify(),
)
```

## API

### Constructors

| Function | Description |
|----------|-------------|
| `NewClientWithPreset(name, ...Option)` | Create a client using a built-in browser fingerprint |
| `NewClientWithJA3(ja3, ...Option)` | Create a client from a JA3 fingerprint string |

### Client Methods

| Method | Description |
|--------|-------------|
| `Do(req)` | Execute an `*http.Request` |
| `Get(url)` | Shorthand GET request |
| `Close()` | Drain idle connections (always call when done) |
| `HTTPClient()` | Access the underlying `*http.Client` |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithTimeout(d)` | 30s | Overall HTTP request timeout |
| `WithDialTimeout(d)` | 10s | TCP connection timeout |
| `WithProxy(url)` | none | Proxy URL (http/https/socks5/socks5h) |
| `WithInsecureSkipVerify()` | false | Skip TLS certificate verification |
| `WithALPN(protocols)` | `["h2", "http/1.1"]` | Override ALPN protocols |

### Available Presets

| Preset | Description |
|--------|-------------|
| `chrome` | Latest Chrome (auto-updated) |
| `chrome_120` | Chrome 120 |
| `chrome_131` | Chrome 131 |
| `chrome_133` | Chrome 133 |
| `chrome_145` | Chrome 145 |
| `firefox` | Latest Firefox (auto-updated) |
| `firefox_105` | Firefox 105 |
| `firefox_120` | Firefox 120 |
| `safari` | Latest Safari |
| `edge` | Latest Edge |
| `ios` | iOS Safari |
| `android` | Android OkHttp |
| `randomized` | Random valid fingerprint |
| `golang` | Default Go TLS (no mimicry) |

Preset names are case-insensitive.

## JA3 Format

JA3 is a standard for fingerprinting TLS clients. The string format is:

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
```

Fields are comma-separated. Values within each field are hyphen-separated. All values are decimal.

Example (Chrome 145):

```
771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0
```

The JA3 parser handles modern extensions including:
- ECH (65037) -- Encrypted Client Hello
- ALPS (17613) -- Application-Layer Protocol Settings
- X25519MLKEM768 (4588) -- Post-quantum key exchange
- GREASE values -- Automatically detected and handled

You can capture JA3 strings from [tls.peet.ws](https://tls.peet.ws/api/all) or [ja3er.com](https://ja3er.com/).

### Using the JA3 Parser Directly

The `ja3` sub-package can be used independently:

```go
import "github.com/KakashiHatake324/tls-client/ja3"

spec, err := ja3.Parse("771,4865-4866-4867,...,29-23-24,0")
if err != nil {
    log.Fatal(err)
}

// Inspect parsed fields
fmt.Println(spec.TLSVersion)     // 771
fmt.Println(spec.CipherSuites)   // [4865 4866 4867 ...]
fmt.Println(spec.EllipticCurves) // [29 23 24]

// Convert to utls.ClientHelloSpec for use with uTLS directly
helloSpec := spec.ClientHelloSpec()
```

## Project Structure

```
tls-client/
├── client.go              TLS client with preset/JA3 support, proxy, connection pooling
├── client_test.go          Integration tests against tls.peet.ws
├── ja3/
│   ├── parser.go           JA3 string parser -> utls.ClientHelloSpec
│   └── parser_test.go      Unit tests for the parser
├── cmd/
│   └── example/
│       └── main.go         CLI demo tool
├── go.mod
└── go.sum
```

## Tests

### Unit Tests (offline, fast)

```bash
go test ./ja3/ -v
```

Tests JA3 string parsing, field extraction, error handling, GREASE detection, and MD5 hashing.

### Integration Tests (requires network)

```bash
go test -v -timeout 60s
```

Sends requests to [tls.peet.ws/api/all](https://tls.peet.ws/api/all) and verifies the fingerprint the server sees matches what was configured. Tests include:

| Test | What it verifies |
|------|-----------------|
| `TestPresetChrome` | Chrome 145 preset negotiates TLS 1.3, sends correct ciphers, includes X25519MLKEM768 |
| `TestPresetFirefox` | Firefox preset negotiates TLS 1.3 |
| `TestJA3String` | Chrome 145 JA3 string reproduces the exact JA3 hash `158072012d190684f7ee6f53b394df35` |
| `TestJA3StringSimple` | Simpler JA3 without ECH/ALPS matches exactly |
| `TestClientClose` | `Close()` works without error |

Skip integration tests in CI with:

```bash
go test -short ./...
```

### Run Everything

```bash
go test -v ./... -timeout 60s
```

## CLI Demo

```bash
go run ./cmd/example/ -preset chrome
go run ./cmd/example/ -ja3 '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0'
go run ./cmd/example/ -preset firefox -url https://httpbin.org/get
```

## Dependencies

| Module | Purpose |
|--------|---------|
| [refraction-networking/utls](https://github.com/refraction-networking/utls) | TLS ClientHello manipulation |
| [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) | SOCKS5 proxy support |

## License

MIT
