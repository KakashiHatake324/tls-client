package tlsclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/andybalholm/brotli"
	http "github.com/saucesteals/fhttp"
)

// Response wraps a completed HTTP request made through the Client helpers.
// Body is fully read and already decompressed (gzip, br, deflate).
type Response struct {
	StatusCode int
	Status     string
	Body       []byte
	Headers    http.Header
	Cookies    []*http.Cookie
	Request    *http.Request
	Raw        *http.Response // underlying response; Raw.Body is already closed — read from Body instead
}

// String returns the response body as a UTF-8 string.
func (r *Response) String() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// JSON decodes the response body into v.
func (r *Response) JSON(v any) error {
	if r == nil {
		return fmt.Errorf("tlsclient: nil response")
	}
	return json.Unmarshal(r.Body, v)
}

// OK reports whether the status code is in the 2xx range.
func (r *Response) OK() bool {
	return r != nil && r.StatusCode >= 200 && r.StatusCode < 300
}

// RequestOption configures a single HTTP request.
type RequestOption func(*requestConfig)

type requestConfig struct {
	ctx            context.Context
	headers        http.Header
	headerOrder    []string
	query          url.Values
	host           string
	acceptedStatus []int
	bodyOverride   io.Reader
	bodyErr        error
	contentType    string
}

// WithContext attaches a context to the request.
func WithContext(ctx context.Context) RequestOption {
	return func(c *requestConfig) { c.ctx = ctx }
}

// WithHeader sets a single request header.
func WithHeader(key, value string) RequestOption {
	return func(c *requestConfig) {
		if c.headers == nil {
			c.headers = make(http.Header)
		}
		c.headers.Set(key, value)
	}
}

// WithHeaders sets multiple headers at once. Later keys replace earlier ones.
func WithHeaders(h map[string]string) RequestOption {
	return func(c *requestConfig) {
		if c.headers == nil {
			c.headers = make(http.Header)
		}
		for k, v := range h {
			c.headers.Set(k, v)
		}
	}
}

// WithHeaderMap copies an http.Header onto the request. A "Header-Order" key
// inside the map is treated as the header order directive (equivalent to
// WithHeaderOrder) and is not sent on the wire.
func WithHeaderMap(h http.Header) RequestOption {
	return func(c *requestConfig) {
		if c.headers == nil {
			c.headers = make(http.Header)
		}
		for k, values := range h {
			if strings.EqualFold(k, "header-order") {
				c.headerOrder = append([]string(nil), values...)
				continue
			}
			for _, v := range values {
				c.headers.Add(k, v)
			}
		}
	}
}

// WithHeaderOrder sets the order in which headers are written to the wire.
// Keys should be canonical (e.g. "User-Agent").
func WithHeaderOrder(keys ...string) RequestOption {
	return func(c *requestConfig) {
		c.headerOrder = append([]string(nil), keys...)
	}
}

// WithQuery appends URL query parameters to the request URL.
func WithQuery(q url.Values) RequestOption {
	return func(c *requestConfig) { c.query = q }
}

// WithRequestHost overrides the Host / :authority header for this request.
func WithRequestHost(host string) RequestOption {
	return func(c *requestConfig) { c.host = host }
}

// WithAcceptedStatus makes Request return an error if the response status is
// not one of the given codes. The Response is still returned alongside the error.
func WithAcceptedStatus(codes ...int) RequestOption {
	return func(c *requestConfig) {
		c.acceptedStatus = append([]int(nil), codes...)
	}
}

// WithJSON marshals v and sends it as the request body with
// Content-Type: application/json. Overrides the body argument.
func WithJSON(v any) RequestOption {
	return func(c *requestConfig) {
		data, err := json.Marshal(v)
		if err != nil {
			c.bodyErr = fmt.Errorf("tlsclient: WithJSON marshal: %w", err)
			return
		}
		c.bodyOverride = bytes.NewReader(data)
		c.contentType = "application/json"
	}
}

// WithForm url-encodes values and sends them as the request body with
// Content-Type: application/x-www-form-urlencoded. Overrides the body argument.
func WithForm(values url.Values) RequestOption {
	return func(c *requestConfig) {
		c.bodyOverride = strings.NewReader(values.Encode())
		c.contentType = "application/x-www-form-urlencoded"
	}
}

// WithRawBody sets the request body from an io.Reader. Overrides the body argument.
func WithRawBody(r io.Reader) RequestOption {
	return func(c *requestConfig) { c.bodyOverride = r }
}

// Get sends a GET request.
func (c *Client) Get(rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodGet, rawURL, nil, opts...)
}

// Post sends a POST request. See Request for body handling.
func (c *Client) Post(rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodPost, rawURL, body, opts...)
}

// Put sends a PUT request.
func (c *Client) Put(rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodPut, rawURL, body, opts...)
}

// Patch sends a PATCH request.
func (c *Client) Patch(rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodPatch, rawURL, body, opts...)
}

// Delete sends a DELETE request.
func (c *Client) Delete(rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodDelete, rawURL, nil, opts...)
}

// Head sends a HEAD request.
func (c *Client) Head(rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodHead, rawURL, nil, opts...)
}

// Options sends an OPTIONS request.
func (c *Client) Options(rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Request(http.MethodOptions, rawURL, nil, opts...)
}

// Request sends an HTTP request with the given method, URL, and body.
// The body argument accepts nil, []byte, string, or io.Reader. For JSON or
// form bodies, use WithJSON or WithForm instead.
func (c *Client) Request(method, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("tlsclient: client is nil")
	}

	cfg := &requestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.bodyErr != nil {
		return nil, cfg.bodyErr
	}
	if cfg.ctx == nil {
		cfg.ctx = context.Background()
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: parse url: %w", err)
	}
	if len(cfg.query) > 0 {
		existing := u.Query()
		for k, vs := range cfg.query {
			for _, v := range vs {
				existing.Add(k, v)
			}
		}
		u.RawQuery = existing.Encode()
	}

	reader, err := resolveBody(body, cfg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(cfg.ctx, method, u.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: new request: %w", err)
	}

	for k, values := range cfg.headers {
		if strings.EqualFold(k, "host") {
			if len(values) > 0 {
				req.Host = values[0]
			}
			continue
		}
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if cfg.host != "" {
		req.Host = cfg.host
	}
	if cfg.contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", cfg.contentType)
	}
	if len(cfg.headerOrder) > 0 {
		req.Header[http.HeaderOrderKey] = append([]string(nil), cfg.headerOrder...)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("tlsclient: do: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tlsclient: read body: %w", err)
	}

	decoded := decodeBody(raw, resp.Header.Get("Content-Encoding"))

	out := &Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Body:       decoded,
		Headers:    resp.Header.Clone(),
		Cookies:    resp.Cookies(),
		Request:    resp.Request,
		Raw:        resp,
	}

	if len(cfg.acceptedStatus) > 0 && !slices.Contains(cfg.acceptedStatus, resp.StatusCode) {
		return out, fmt.Errorf("tlsclient: unexpected status %s", resp.Status)
	}

	return out, nil
}

func resolveBody(body any, cfg *requestConfig) (io.Reader, error) {
	if cfg.bodyOverride != nil {
		return cfg.bodyOverride, nil
	}
	switch b := body.(type) {
	case nil:
		return nil, nil
	case []byte:
		return bytes.NewReader(b), nil
	case string:
		if b == "" {
			return nil, nil
		}
		return strings.NewReader(b), nil
	case io.Reader:
		return b, nil
	default:
		return nil, fmt.Errorf("tlsclient: unsupported body type %T (use []byte, string, io.Reader, or WithJSON/WithForm)", body)
	}
}

func decodeBody(raw []byte, encoding string) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return raw
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return raw
		}
		return out
	case "br":
		out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return raw
		}
		return out
	case "deflate":
		r := flate.NewReader(bytes.NewReader(raw))
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return raw
		}
		return out
	default:
		return raw
	}
}
