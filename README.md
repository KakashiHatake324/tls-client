# tls-client

A Go module for making HTTP requests with accurate TLS + HTTP/2 fingerprints. Mimic real browsers and devices by using built-in presets, or provide a JA3 string to build a custom fingerprint.

Matches the full fingerprint stack: TLS ClientHello, HTTP/2 SETTINGS, WINDOW_UPDATE, pseudo-header order, priority frames, header ordering, and sec-ch-ua client hints.

Built on [uTLS](https://github.com/refraction-networking/utls) for TLS and [fhttp](https://github.com/saucesteals/fhttp) for HTTP/2 frame control.

## Install

```bash
go get github.com/KakashiHatake324/tls-client
```

Requires Go 1.21+.

## Quick Start

### Browser Preset

```go
import (
    tlsclient "github.com/KakashiHatake324/tls-client"
    http "github.com/saucesteals/fhttp"
)

client, err := tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// client.Info has the matching headers
fmt.Println(client.Info.UserAgent)      // Mozilla/5.0 ... Chrome/145.0.0.0 ...
fmt.Println(client.Info.SecChUA)        // "Not:A-Brand";v="99", "Chromium";v="145", ...
fmt.Println(client.Info.SecChUAPlatform) // "macOS"

resp, err := client.Get("https://tls.peet.ws/api/all")
```

### Custom JA3 String

```go
ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-35-65037-17613-27-11-16-13-18-5-51-23-10-45-65281,4588-29-23-24,0"

client, err := tlsclient.NewClientWithJA3(ja3)
```

HTTP/2 defaults to Chrome settings. Override with `WithH2Profile`:

```go
client, err := tlsclient.NewClientWithJA3(firefoxJA3, tlsclient.WithH2Profile("firefox"))
```

### Random Client From Pool

```go
pool := []tlsclient.BrowserSpec{
    {Browser: "chrome", Version: "145.0.0.0", Platform: "mac"},
    {Browser: "chrome", Version: "145.0.0.0", Platform: "android"},
    {Browser: "firefox", Version: "134.0", Platform: "win"},
    {Browser: "safari", Version: "18.3", Platform: "ios"},
}

client, err := tlsclient.NewClientFromPool(pool)
fmt.Println(client.Info.Browser, client.Info.Platform) // whichever was picked
```

### With Options

```go
client, err := tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac",
    tlsclient.WithProxy("socks5://user:pass@127.0.0.1:1080"),
    tlsclient.WithTimeout(15 * time.Second),
    tlsclient.WithDialTimeout(5 * time.Second),
    tlsclient.WithInsecureSkipVerify(),
)
```

## Requests

The client ships with verb helpers that handle body encoding, header ordering, and response decompression (gzip / br / deflate) automatically. Use them anywhere in any repo as a drop-in HTTP layer.

```go
client, _ := tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac")

resp, err := client.Get("https://api.example.com/v1/users")
if err != nil {
    log.Fatal(err)
}

resp.StatusCode  // int
resp.String()    // decoded body as string
resp.Body        // decoded body as []byte
resp.Headers     // fhttp.Header
resp.Cookies     // []*fhttp.Cookie
resp.OK()        // true if 2xx
```

### Verbs

| Method | Signature |
|--------|-----------|
| `client.Get(url, opts...)` | GET request |
| `client.Post(url, body, opts...)` | POST request |
| `client.Put(url, body, opts...)` | PUT request |
| `client.Patch(url, body, opts...)` | PATCH request |
| `client.Delete(url, opts...)` | DELETE request |
| `client.Head(url, opts...)` | HEAD request |
| `client.Options(url, opts...)` | OPTIONS request |
| `client.Request(method, url, body, opts...)` | Generic request |

The `body` argument accepts `nil`, `[]byte`, `string`, or `io.Reader`. For JSON and form bodies use `WithJSON` or `WithForm` — they set the right `Content-Type` for you.

### Headers

Headers are set with request options. Mix and match as needed — all of these work together.

```go
// Single header
client.Get(url, tlsclient.WithHeader("Authorization", "Bearer "+token))

// Multiple headers from a map
client.Get(url, tlsclient.WithHeaders(map[string]string{
    "Authorization": "Bearer " + token,
    "Accept":        "application/json",
    "X-Client":      "my-app",
}))

// Ordered headers — written to the wire in this order
client.Get(url,
    tlsclient.WithHeaders(map[string]string{
        "User-Agent": client.Info.UserAgent,
        "Accept":     "application/json",
        "Referer":    "https://example.com",
    }),
    tlsclient.WithHeaderOrder("User-Agent", "Accept", "Referer"),
)

// From an existing fhttp.Header (a "Header-Order" key inside the map is
// interpreted as the order directive — useful for porting existing code
// that used map[string][]string with a magic "header-order" key)
h := http.Header{
    "User-Agent":   {client.Info.UserAgent},
    "Accept":       {"application/json"},
    "header-order": {"User-Agent", "Accept"},
}
client.Get(url, tlsclient.WithHeaderMap(h))

// Override the Host / :authority header
client.Get(url, tlsclient.WithRequestHost("internal.example.com"))
```

### Bodies

```go
// JSON body — sets Content-Type: application/json
payload := map[string]any{"name": "Ada", "age": 36}
resp, err := client.Post(url, nil, tlsclient.WithJSON(payload))

// Form body — sets Content-Type: application/x-www-form-urlencoded
form := url.Values{"username": {"ada"}, "password": {"secret"}}
resp, err := client.Post(url, nil, tlsclient.WithForm(form))

// Raw body as a byte slice, string, or io.Reader
resp, err := client.Post(url, []byte(`{"raw":"json"}`))
resp, err := client.Post(url, "plain text")
resp, err := client.Post(url, bytes.NewReader(data))

// Or via option (lets you keep the body param nil for readability)
resp, err := client.Post(url, nil, tlsclient.WithRawBody(bytes.NewReader(data)))
```

### Query Parameters, Context, and Status Validation

```go
resp, err := client.Get(url,
    tlsclient.WithContext(ctx),
    tlsclient.WithQuery(url.Values{"q": {"hello"}, "page": {"2"}}),
    tlsclient.WithAcceptedStatus(200, 201), // returns error if status isn't one of these
)
```

### Decoding Responses

```go
// As a string
text := resp.String()

// As JSON into a struct
var out struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}
if err := resp.JSON(&out); err != nil { ... }

// Raw bytes
fmt.Printf("%d bytes\n", len(resp.Body))
```

### Raw Access

For advanced use cases (custom request construction, streaming bodies, TLS connection state), drop down to `Do`:

```go
req, _ := http.NewRequest("GET", url, nil)
req.Header.Set("User-Agent", client.Info.UserAgent)
resp, err := client.Do(req) // returns *fhttp.Response — you own Body.Close()
```

## Browser + Platform Support

| Browser | win | mac | linux | android | ios | ipados |
|---------|:---:|:---:|:-----:|:-------:|:---:|:------:|
| **chrome** (100+) | x | x | x | x | x | x |
| **edge** (100+) | x | x | x | x | | |
| **brave** (100+) | x | x | x | x | | |
| **firefox** (55+) | x | x | x | x | | |
| **safari** (16+) | | x | | | x | x |
| **okhttp** | | | | x | | |

Notes:
- Chrome/Edge/Brave on iOS and iPadOS use Apple's WebKit TLS stack (iOS TLS fingerprint) with a CriOS user-agent
- Chrome/Edge/Brave on Android send `sec-ch-ua-mobile: ?1` and a mobile user-agent
- Safari only runs on Apple platforms
- OkHttp mimics native Android apps using the OkHttp library

### Example Calls

```go
// Desktop
tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac")
tlsclient.NewClientWithPreset("firefox", "134.0", "win")
tlsclient.NewClientWithPreset("safari", "18.3", "mac")
tlsclient.NewClientWithPreset("edge", "145.0.0.0", "win")

// Mobile
tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "android")
tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "ios")
tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "ipados")
tlsclient.NewClientWithPreset("firefox", "134.0", "android")
tlsclient.NewClientWithPreset("safari", "18.3", "ios")
tlsclient.NewClientWithPreset("safari", "18.3", "ipados")
tlsclient.NewClientWithPreset("okhttp", "4.12.0", "android")
```

## API Reference

### Constructors

| Function | Description |
|----------|-------------|
| `NewClientWithPreset(browser, version, platform, ...Option)` | Mimic a specific browser/version/platform |
| `NewClientWithJA3(ja3, ...Option)` | Build fingerprint from a JA3 string |
| `NewClientFromPool([]BrowserSpec, ...Option)` | Pick a random browser from a pool |

### Client

| Field/Method | Description |
|--------------|-------------|
| `Info` | `ClientInfo` struct with UserAgent, SecChUA, SecChUAMobile, SecChUAPlatform, Browser, Version, Platform |
| `Get/Post/Put/Patch/Delete/Head/Options(url, opts...)` | Verb helpers — return `*Response` with decoded body |
| `Request(method, url, body, opts...)` | Generic request — returns `*Response` |
| `Do(req)` | Execute a raw `*fhttp.Request`, returns `*fhttp.Response` |
| `Close()` | Release idle connections |
| `Jar()` | Access the cookie jar |
| `HTTPClient()` | Access the underlying `*fhttp.Client` |

### Client Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithTimeout(d)` | 30s | HTTP request timeout |
| `WithDialTimeout(d)` | 10s | TCP dial timeout |
| `WithProxy(url)` | none | Proxy URL (http/https/socks5) |
| `WithInsecureSkipVerify()` | false | Skip TLS cert verification |
| `WithH2Profile(browser)` | `"chrome"` | HTTP/2 profile for JA3 mode (`"chrome"`, `"firefox"`, `"safari"`) |
| `WithCookieJar(jar)` | auto | Custom cookie jar |
| `WithNoCookieJar()` | | Disable cookies |
| `WithNoRedirects()` | follow | Don't follow redirects |
| `WithMaxRedirects(n)` | 10 | Cap redirect chain length |
| `WithForceTLS12()` | false | Pin TLS 1.2 handshake |
| `WithBypassCache()` | false | Randomize host casing per request |
| `WithPinnedCerts(pins...)` | none | SPKI SHA-256 SSL pins |

### Request Options

Passed to `Get`, `Post`, `Request`, etc. Scope is a single request.

| Option | Description |
|--------|-------------|
| `WithContext(ctx)` | Attach a `context.Context` |
| `WithHeader(key, value)` | Set a single header |
| `WithHeaders(map[string]string)` | Set multiple headers |
| `WithHeaderMap(fhttp.Header)` | Set headers from an `fhttp.Header` — `"Header-Order"` key is treated as order directive |
| `WithHeaderOrder(keys...)` | Order headers on the wire |
| `WithQuery(url.Values)` | Append query parameters |
| `WithRequestHost(host)` | Override Host / :authority |
| `WithJSON(v)` | JSON body, sets `Content-Type: application/json` |
| `WithForm(url.Values)` | Form body, sets `Content-Type: application/x-www-form-urlencoded` |
| `WithRawBody(r)` | Body from an `io.Reader` |
| `WithAcceptedStatus(codes...)` | Error if response status isn't in the list |

### Response

| Field/Method | Description |
|--------------|-------------|
| `StatusCode` | HTTP status code |
| `Status` | Status text (e.g. `"200 OK"`) |
| `Body` | Decoded response body as `[]byte` |
| `Headers` | `fhttp.Header` |
| `Cookies` | `[]*fhttp.Cookie` |
| `Request` | The request that produced this response |
| `Raw` | Underlying `*fhttp.Response` (body already drained) |
| `String()` | Body as a string |
| `JSON(&v)` | Decode body into `v` |
| `OK()` | True if status is 2xx |

## Cookie Jar

Cookies are handled automatically by default (like a real browser):

```go
client, _ := tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac")

// Cookies from the first response are sent in subsequent requests
client.Get("https://example.com/login")
client.Get("https://example.com/dashboard") // cookies included

// Inspect cookies
cookies := client.Jar().Cookies(someURL)
```

## What Gets Matched

| Signal | Matched |
|--------|---------|
| TLS ClientHello (ciphers, extensions, curves, key shares) | Yes |
| JA3 / JA4 / Peetprint | Yes |
| HTTP/2 SETTINGS frame (values and order) | Yes |
| HTTP/2 WINDOW_UPDATE (connection flow) | Yes |
| HTTP/2 HEADERS priority (weight, dependency, exclusive) | Yes |
| Pseudo-header order (:method, :authority, :scheme, :path) | Yes |
| Header order (randomized like Chrome 106+) | Yes |
| User-Agent | Yes |
| sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform | Yes (Chromium only) |
| Cookies | Yes (auto jar) |

## JA3 Format

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
```

Fields are comma-separated. Values within each field are hyphen-separated. All values are decimal.

The parser handles ECH (65037), ALPS (17613), X25519MLKEM768 (4588), and GREASE values.

Capture JA3 strings from [tls.peet.ws](https://tls.peet.ws/api/all) or [ja3er.com](https://ja3er.com/).

### JA3 Sub-Package

```go
import "github.com/KakashiHatake324/tls-client/ja3"

spec, _ := ja3.Parse("771,4865-4866-4867,...,29-23-24,0")
fmt.Println(spec.TLSVersion)     // 771
fmt.Println(spec.CipherSuites)   // [4865 4866 4867 ...]

helloSpec := spec.ClientHelloSpec() // *utls.ClientHelloSpec
```

## Project Structure

```
tls-client/
├── client.go          Client API, constructors, options
├── profiles.go        Browser fingerprint profiles (TLS + HTTP/2 + headers)
├── transport.go       Transport wrapper (header ordering, H2 config)
├── client_test.go     Integration tests
├── ja3/
│   ├── parser.go      JA3 string parser
│   └── parser_test.go
└── cmd/example/
    └── main.go        CLI demo
```

## Tests

```bash
# Unit tests (offline)
go test ./ja3/ -v

# Integration tests (hits tls.peet.ws)
go test -v -timeout 60s

# Skip network tests
go test -short ./...

# Everything
go test -v ./... -timeout 60s
```

## CLI Demo

```bash
go run ./cmd/example/ -browser chrome -version 145.0.0.0 -platform mac
go run ./cmd/example/ -browser firefox -version 134.0 -platform win
go run ./cmd/example/ -browser safari -version 18.3 -platform ios
go run ./cmd/example/ -ja3 '771,4865-4866-4867-...,4588-29-23-24,0'
```

## Dependencies

| Module | Purpose |
|--------|---------|
| [refraction-networking/utls](https://github.com/refraction-networking/utls) | TLS ClientHello manipulation |
| [saucesteals/fhttp](https://github.com/saucesteals/fhttp) | HTTP/2 frame control + header ordering |

## License

MIT
