package tlsclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	http "github.com/saucesteals/fhttp"
)

// decompressResponse fills the gaps in fhttp's own decompression, then clears
// the encoding headers so the response looks to the caller exactly as it would
// to a browser.
//
// fhttp decodes gzip/br/deflate on HTTP/2 unconditionally (h2_bundle.go:8977)
// but leaves Content-Encoding on the response, so the header alone cannot tell
// a caller whether the bytes are still compressed. res.Uncompressed is the
// reliable signal and is what we key off. Two cases reach here still encoded:
// HTTP/1.1 responses, where fhttp decodes only when it added Accept-Encoding
// itself (transport.go:2199), and zstd on any protocol, which fhttp does not
// handle at all. Both would otherwise hand compressed bytes to an io.ReadAll
// with no error.
//
// Decoding is lazy: the wrapper is built on first Read, so an empty body (204,
// HEAD) never fails on a header the compressor cannot find.
func decompressResponse(res *http.Response) *http.Response {
	if res == nil || res.Body == nil {
		return res
	}

	if res.Uncompressed {
		// Already decoded upstream; the stale header would only mislead.
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		return res
	}

	encoding := lastEncoding(res.Header.Get("Content-Encoding"))
	newReader, ok := decoderFor(encoding)
	if !ok {
		return res
	}

	res.Body = &lazyDecoder{src: res.Body, wrap: newReader}
	res.Header.Del("Content-Encoding")
	res.Header.Del("Content-Length")
	res.ContentLength = -1
	res.Uncompressed = true
	return res
}

// lastEncoding returns the single coding to undo. Content-Encoding is formally
// a list applied in order, but servers in practice send exactly one; taking the
// last entry undoes the outermost coding, which is the only one we could
// meaningfully strip anyway.
func lastEncoding(value string) string {
	parts := strings.Split(value, ",")
	return strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
}

func decoderFor(encoding string) (func(io.Reader) (io.Reader, error), bool) {
	switch encoding {
	case "gzip", "x-gzip":
		return func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }, true
	case "br":
		return func(r io.Reader) (io.Reader, error) { return brotli.NewReader(r), nil }, true
	case "zstd":
		return func(r io.Reader) (io.Reader, error) {
			d, err := zstd.NewReader(r)
			if err != nil {
				return nil, err
			}
			return d.IOReadCloser(), nil
		}, true
	case "deflate":
		return newDeflateReader, true
	default:
		return nil, false
	}
}

// newDeflateReader handles both readings of "deflate": the zlib-wrapped stream
// the HTTP spec calls for, and the raw DEFLATE stream many servers actually
// send. The zlib header is two bytes whose first nibble is 8 (CM=deflate), so
// one buffered peek decides which.
func newDeflateReader(r io.Reader) (io.Reader, error) {
	head := make([]byte, 2)
	n, err := io.ReadFull(r, head)
	head = head[:n]
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}

	replayed := io.MultiReader(bytes.NewReader(head), r)
	if n == 2 && head[0]&0x0f == 0x08 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
		if zr, zerr := zlib.NewReader(replayed); zerr == nil {
			return zr, nil
		}
		replayed = io.MultiReader(bytes.NewReader(head), r)
	}
	return flate.NewReader(replayed), nil
}

// lazyDecoder builds the decompressing reader on first Read so that a body with
// no bytes in it never surfaces the compressor's "unexpected EOF".
type lazyDecoder struct {
	src  io.ReadCloser
	wrap func(io.Reader) (io.Reader, error)

	decoded io.Reader
	err     error
}

func (d *lazyDecoder) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.decoded == nil {
		decoded, err := d.wrap(d.src)
		if err != nil {
			d.err = err
			return 0, err
		}
		d.decoded = decoded
	}
	return d.decoded.Read(p)
}

func (d *lazyDecoder) Close() error {
	if c, ok := d.decoded.(io.Closer); ok {
		c.Close()
	}
	return d.src.Close()
}
