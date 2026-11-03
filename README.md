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

client, err := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac")
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// client.Info has the matching headers
fmt.Println(client.Info.UserAgent)      // Mozilla/5.0 ... Chrome/152.0.0.0 ...
fmt.Println(client.Info.SecChUA)        // "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
fmt.Println(client.Info.SecChUAPlatform) // "macOS"

resp, err := client.Get("https://tls.peet.ws/api/all")
```

### From a User-Agent

If you already have a UA string, let the library pick the preset for you:

```go
client, err := tlsclient.NewClientWithUserAgent(
    "Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36",
)
```

The browser, version, platform, and OS version are read out of the UA, and
requests go out with that exact string rather than the one the preset would
synthesize. Recognized tokens are Chrome, CriOS, Edg/Edge/EdgA/EdgiOS, Brave,
Firefox, FxiOS, Safari's `Version/`, and okhttp. Chromium re-skins
(Samsung Internet, Yandex, Opera) resolve to their underlying Chrome version.

Two fallbacks keep real-world traffic working. An iPhone or iPad UA with no
browser token is an in-app WebView — the Google app, Facebook, Instagram,
Firefox for iOS — and since Apple requires every iOS browser to render with
WebKit over the system TLS stack, they all handshake like Safari of the same OS
version. A UA with no platform token at all, which is typical of crawlers and
headless tooling, falls back to Linux; Chromium's ClientHello is identical
across desktop platforms, so this only affects the client hints.

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
    {Browser: "chrome", Version: "152.0.0.0", Platform: "mac"},
    {Browser: "chrome", Version: "152.0.0.0", Platform: "android"},
    {Browser: "firefox", Version: "134.0", Platform: "win"},
    {Browser: "safari", Version: "18.3", Platform: "ios"},
}

client, err := tlsclient.NewClientFromPool(pool)
fmt.Println(client.Info.Browser, client.Info.Platform) // whichever was picked
```

### With Options

```go
client, err := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac",
    tlsclient.WithProxy("socks5://user:pass@127.0.0.1:1080"),
    tlsclient.WithTimeout(15 * time.Second),
    tlsclient.WithDialTimeout(5 * time.Second),
    tlsclient.WithInsecureSkipVerify(),
)
```

## Requests

The client ships with verb helpers that handle body encoding, header ordering, and response decompression (gzip / br / deflate) automatically. Use them anywhere in any repo as a drop-in HTTP layer.

```go
client, _ := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac")

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
| **chrome** (58+) | x | x | x | x | x | x |
| **edge** (58+) | x | x | x | x | | |
| **brave** (58+) | x | x | x | x | | |
| **firefox** (55+) | x | x | x | x | | |
| **safari** (11+) | | x | | | x | x |
| **okhttp** | | | | x | | |

Notes:
- Chrome/Edge/Brave on iOS and iPadOS use Apple's WebKit TLS stack (iOS TLS fingerprint) with a CriOS user-agent
- Chrome/Edge/Brave on Android send `sec-ch-ua-mobile: ?1` and a mobile user-agent
- Safari only runs on Apple platforms
- OkHttp mimics native Android apps using the OkHttp library

The version floors are set by the oldest ClientHello uTLS ships a preset for.
Versions above a floor but below the modern specs land on the closest
era-appropriate preset, so a long-EOL build still gets a plausible fingerprint
rather than an error: Chrome 58-131 and Safari 11-15 are modelled this way.
Versions below a floor are rejected by `NewClientWithPreset`, and raised to the
floor by `NewClientWithUserAgent`.

Version-dependent behavior worth knowing about:

| Preset | Boundary | Effect |
|---|---|---|
| chrome/edge/brave | 132+ | One ClientHello for every desktop and Android platform: `X25519MLKEM768` (4588), ALPS codepoint 17613, GREASE ECH, brotli certificate compression. Ciphers, extensions, and groups are unchanged through Chrome 152. |
| chrome/edge/brave | 150+ | Advertises the post-quantum ML-DSA signature schemes mldsa44/65/87 ahead of the classical algorithms. Chrome 150 turned this on for stable. Changes JA4_c and peetprint; JA3 and JA3N cannot see it. Override with `WithoutMLDSA()`. |
| chrome/edge/brave | 152+ | Sends the `trust_anchors` extension (0xca34) on every hello with the 32 Chrome Root Store IDs, taking the extension count to 17, and prepends a per-connection GREASE value to `signature_algorithms`. Moves both JA3N and JA4. Override with `WithoutTrustAnchors()`. |
| firefox | 132+ desktop | Offers the hybrid post-quantum group `X25519MLKEM768` (4588). Not sent on Android, matching real Firefox. |
| firefox | 151+ | Drops the ECDSA-CBC cipher 49161, taking the list from 17 suites to 16. |
| safari | 11-15 | Uses the era-matched uTLS iOS preset on every Apple platform. These builds predate `NO_RFC7540_PRIORITIES` (RFC 9218, 2022), so they also use the classic Safari HTTP/2 SETTINGS shape rather than the current one. Safari 11-12 negotiate TLS 1.2. |
| safari | 26+ | Offers `X25519MLKEM768` on macOS, iOS, and iPadOS, which Apple enabled by default across the 26 releases. |
| okhttp | 5+ | Uses a TLS 1.3 spec that negotiates HTTP/2. Older versions fall back to a TLS 1.2-only fingerprint with no ALPN, so they speak HTTP/1.1 and carry no Akamai fingerprint. |

Chrome, Edge, and Brave on `ios` and `ipados` are WebKit shells over Apple's TLS
stack, so their ClientHello follows the OS rather than the browser version. They
always use the current Apple shape, including the post-quantum group.

### Example Calls

```go
// Desktop
tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac")
tlsclient.NewClientWithPreset("firefox", "151.0", "win")
tlsclient.NewClientWithPreset("safari", "18.3", "mac")
tlsclient.NewClientWithPreset("edge", "152.0.0.0", "win")

// Mobile
tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "android")
tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "ios")
tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "ipados")
tlsclient.NewClientWithPreset("firefox", "151.0", "android")
tlsclient.NewClientWithPreset("safari", "18.3", "ios")
tlsclient.NewClientWithPreset("safari", "18.3", "ipados")
tlsclient.NewClientWithPreset("okhttp", "5.3.0", "android")
```

## API Reference

### Constructors

| Function | Description |
|----------|-------------|
| `NewClientWithPreset(browser, version, platform, ...Option)` | Mimic a specific browser/version/platform |
| `NewClientWithUserAgent(ua, ...Option)` | Infer the preset from a User-Agent string and send that exact UA |
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
| `WithTrustAnchors(ids...)` | off | Send `trust_anchors` (0xca34), Chrome 141+ Finch experiment |
| `WithMLDSA()` | auto | Force ML-DSA signature schemes on (already the default for Chrome 150+) |
| `WithoutMLDSA()` | auto | Force ML-DSA off, reproducing the pre-Chrome-150 shape |
| `WithoutTrustAnchors()` | auto | Force `trust_anchors` off, reproducing the 16-extension shape of Chrome 132-151 |
| `WithGoogleHeaders(g)` | off | Send `x-client-data` and the `x-browser-*` headers to Google origins |

#### Chrome ClientHello Options

`WithMLDSA()` / `WithoutMLDSA()` control the post-quantum ML-DSA schemes mldsa44
(`0x0904`), mldsa65 (`0x0905`), and mldsa87 (`0x0906`) at the front of
`signature_algorithms`.

**You normally need neither.** Chrome 150 shipped "Support for ML-DSA in TLS
enabled by default" to stable on Android, ChromeOS, Linux, macOS, Windows, and
Fuchsia, so the presets send them automatically from 150 up and omit them below.
Chrome advertises the schemes on every connection even though an ML-DSA
certificate only validates against a manually configured root.

```go
// Chrome 151/152 — ML-DSA included automatically.
client, _ := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac")

// Reproduce a pre-150 capture from a modern version.
client, _ = tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac",
    tlsclient.WithoutMLDSA())

// Add the schemes to an older version.
client, _ = tlsclient.NewClientWithPreset("chrome", "145.0.0.0", "mac",
    tlsclient.WithMLDSA())
```

This is worth understanding because **JA3 and JA3N do not encode signature
algorithms**. A client stuck on the pre-150 list still reports a perfect JA3N
match against Chrome while its JA4_c and peetprint are both wrong:

| | Chrome 132-149 | Chrome 150+ |
|---|---|---|
| JA3N | `8e19337e7524d2573be54efb2b0784c9` | `8e19337e7524d2573be54efb2b0784c9` (same) |
| JA4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| peetprint | `1d4ffe9b0e34acac0bd883fa7f79d7b5` | `67c3e9111bed9e7f03d2f21d6d88994b` |

#### Google-only headers: `x-client-data` and `x-browser-*`

Chrome sends five extra headers to Google-owned origins and to nowhere else.
`WithGoogleHeaders` reproduces that, attaching them only to Google-associated
hosts over HTTPS — sending them to an unrelated server would be a giveaway on
its own, so the scope matters as much as the values.

```go
client, _ := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac",
    tlsclient.WithGoogleHeaders(tlsclient.GoogleHeaders{
        ClientData: "CM6XywE=",                     // captured from a real Chrome
        Validation: "S7hKo5PWMhrUgzQMwm5wWB2agsI=", // captured from a real Chrome
    }))
```

Captured from Chrome 151.0.7922.174 loading `https://www.google.com/`, the set
looks like this — note the copyright wording is "All Rights Reserved.", not the
lowercase form quoted in most write-ups:

```
x-browser-channel: stable
x-browser-year: 2026
x-browser-validation: S7hKo5PWMhrUgzQMwm5wWB2agsI=
x-browser-copyright: Copyright 2026 Google LLC. All Rights Reserved.
x-client-data: CM6XywE=
```

The three constant headers are generated for you. The two value-bearing ones are
**opt-in and omitted when empty**, because neither can be derived correctly from
scratch:

**`x-client-data`** is a base64-encoded `ClientVariations` protobuf listing the
Finch variation IDs the browser is enrolled in — field 1 for reporting-only IDs,
field 3 for ones that trigger server-side behavior. `ClientDataHeader` encodes
it, and the encoder is pinned against real captures:

```go
tlsclient.ClientDataHeader([]int32{3328974}, nil) // "CM6XywE="
```

The IDs come from the browser's variations seed, so they differ per install —
two fresh Chrome profiles produced `CM6XywE=` and `CPHsygE=` minutes apart.
There is no universally correct value; use one you captured, or IDs you know.

**`x-browser-validation`** is an integrity hash introduced in Chrome 134. The
algorithm is open source — `chrome/common/request_header_integrity/request_header_integrity_url_loader_throttle.cc`
in public chromium/src, behind `enable_request_header_integrity = is_chrome_branded`:

```cpp
base::Base64Encode(base::SHA1Hash(base::as_byte_span(
    std::string(kIntegritySeed) + google_apis::GetAPIKey() +
    embedder_support::GetUserAgent())));
```

So it is `base64(sha1(seed + api_key + user_agent))`. `BrowserValidation(secret, ua)`
implements exactly this, with `secret = seed + api_key`. The catch is the secret:

> Both `kIntegritySeed` and the API key come from a **closed** Chromium submodule
> (`src/chrome/common/request_header_integrity/internal`, `src/google_apis/internal`),
> pulled only for official Google builds. The public tree sets the seed to `""`
> and even compiles the header names as `X-Placeholder-1..4` — which is why these
> strings live in the Google Chrome binary but not in open-source Chromium. The
> seed was added around November 2025, before the Chrome 151 branch, which is
> exactly why the older `sha1(api_key + ua)` formula reproduces Chrome ~134–143
> captures but not 151's `bvcR2nfcbw0bPYHPJRO+bpzN01M=`.

SHA-1 is not invertible, so a captured `(UA, value)` pair does not reveal the
secret, and one value does not let you compute another. Unless you extract the
secret from the matching Chrome binary and pass it as `ValidationSecret`, capture
the real header and pass it as `Validation`. A wrong integrity header is a louder
signal than a missing one, so leave it empty otherwise.

`ChromeAPIKey(platform)` returns the public per-platform key (selected by build
platform, not by the spoofed UA); with an empty seed it reproduces the pre-2025
formula, useful only for older Chrome.

##### Capturing real values

Chrome will hand you its own headers through netlog:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --user-data-dir=/tmp/chrome-capture \
  --log-net-log=/tmp/netlog.json --net-log-capture-mode=IncludeSensitive \
  --virtual-time-budget=8000 "https://www.google.com/"

grep -o '"x-[a-z-]*: [^"]*"' /tmp/netlog.json | sort -u
```

The values are tied to that browser build, its variations seed, and its
User-Agent, so recapture when you change the version you impersonate.

`WithTrustAnchors()` is a genuine opt-in. It adds the `trust_anchors` extension
from [draft-ietf-tls-trust-anchor-ids](https://tlswg.org/tls-trust-anchor-ids/draft-ietf-tls-trust-anchor-ids.html),
which Chrome 141+ can send behind the `TLSTrustAnchorIDs` Finch experiment. A
captured Chromium 145.0.7568.0 build does send it with an empty list; stable
Chrome 151.0.7922.174 does not. Enabling it moves the JA4 prefix from
`t13d1516h2` (16 extensions) to `t13d1517h2` (17):

```go
// Empty list — what Chrome sends on an initial connection.
client, _ := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac",
    tlsclient.WithTrustAnchors())

// Or advertise specific IDs, as dotted-decimal relative OIDs.
client, _ = tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac",
    tlsclient.WithTrustAnchors("32473.1", "32473.2.1"))
```

All three apply to Chromium presets (`chrome`, `edge`, `brave`) on version 132+
and are ignored by Firefox, Safari, and okhttp.

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
client, _ := tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac")

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
| JA4 / JA3N / Peetprint | Yes |
| Raw JA3 | Intentionally varies per connection (see below) |
| HTTP/2 SETTINGS frame (values and order) | Yes |
| HTTP/2 WINDOW_UPDATE (connection flow) | Yes |
| HTTP/2 HEADERS priority (weight, dependency, exclusive) | Yes |
| Pseudo-header order (:method, :authority, :scheme, :path) | Yes |
| Header order (randomized like Chrome 106+) | Yes |
| User-Agent | Yes |
| sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform | Yes (Chromium only) |
| Cookies | Yes (auto jar) |
| `x-client-data` / `x-browser-*` on Google origins | Opt-in (`WithGoogleHeaders`) |

### A note on JA3 stability

Chrome has shuffled its ClientHello extension order on every connection since
version 110, so a raw JA3 hash is not a stable identifier for Chrome and this
library reproduces that shuffling. Expect a different `ja3_hash` on every
request from a Chromium preset; matching a single fixed JA3 hash would itself be
a fingerprinting tell.

The stable equivalents are **JA4**, which sorts extensions, and **JA3N**, the
normalized JA3 that sorts the extension field. Chrome's ClientHello is
platform-independent from version 132 on, so mac, Windows, Linux, Android, Edge,
and Brave all produce the same values — but the values themselves moved twice,
giving three eras:

| Chrome | JA3N | JA4 |
|---|---|---|
| 132-149 | `8e19337e7524d2573be54efb2b0784c9` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| 150-151 | `8e19337e7524d2573be54efb2b0784c9` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| 152+ | `bd4930bd9b000ee684830e44bab76fdf` | `t13d1517h2_8daaf6152771_cb7bf5808d99` |

Look at the 150 row: **JA3N is identical either side of it.** ML-DSA lives in
`signature_algorithms`, which JA3 does not encode, so a JA3N check reports a
perfect match for a client that no longer resembles Chrome. Chrome 152 then adds
the `trust_anchors` extension, which JA3N does see.

`ja4_test.go` marshals the ClientHello each preset would send and recomputes
JA3, JA3N, and JA4 from the raw bytes, so those values are pinned offline as
well as against tls.peet.ws:

```bash
go test -short -run TestChromeModernFingerprint -v
```

**Check more than one fingerprint.** Each of these has a blind spot, and a
preset can look perfect in one while being wrong in another:

- **JA3 / JA3N** ignore signature algorithms entirely. The Chrome 150 ML-DSA
  change is invisible to them — JA3N is byte-identical before and after.
- **JA4** ignores `supported_groups`, so a missing post-quantum group does not
  show up. It does cover signature algorithms, via JA4_c.
- **peetprint** covers both, which makes it the best single check.

### Verifying against a real browser

The surest way to check a preset is to capture what the real browser sends. Run
a listener that dumps the ClientHello, point the browser at it, then point this
library at it and compare:

```bash
go run ./cmd/hellodump -addr :8443          # prints JA3, JA3N, JA4 per connection

# then, in a browser: https://localhost:8443
# and from Go: tlsclient.NewClientWithPreset("chrome", "152.0.0.0", "mac") → GET https://localhost:8443
```

The certificate error the browser shows is expected and harmless: the handshake
never completes, because the ClientHello is all that gets read. This is how the
Chrome 150 ML-DSA change was caught — it was invisible to the JA3N check the
test suite had at the time.

## JA3 Format

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
```

Fields are comma-separated. Values within each field are hyphen-separated. All values are decimal.

The parser handles ECH (65037), ALPS (17613), X25519MLKEM768 (4588), trust_anchors
(51764), and GREASE values.

Note that `TLSVersion` is the ClientHello `legacy_version`, which RFC 8446 pins
to 771 (TLS 1.2) for every TLS 1.3 client; 1.3 is negotiated through the
supported_versions extension instead. The parser therefore infers TLS 1.3
support from the presence of a TLS 1.3-only cipher suite (4865-4867) rather than
from this field, so a browser JA3 negotiates TLS 1.3 and yields a `t13d` JA4.

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
├── useragent.go       User-Agent parsing and preset inference
├── client_test.go     Integration tests
├── ja4_test.go        Offline JA3/JA4 verification (no network)
├── fingerprint_test.go  Per-version fingerprint pins (JA4/JA3N)
├── testdata/
│   └── useragents.json  Real-world User-Agent corpus
├── ja3/
│   ├── parser.go      JA3 string parser
│   └── parser_test.go
└── cmd/
    ├── example/
    │   └── main.go    CLI demo
    └── hellodump/
        └── main.go    ClientHello capture server (JA3/JA3N/JA4 off the wire)
```

## Tests

```bash
# Unit tests (offline), including the JA3/JA4 fingerprint pins
go test -short ./... -v
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
go run ./cmd/example/ -browser chrome -version 152.0.0.0 -platform mac
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
