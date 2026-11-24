// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package s3

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/XTXMarkets/ternfs/go/core/log"
	"github.com/XTXMarkets/ternfs/go/msgs"
)

const (
	crc32Header = checksumPrefix + "crc32"
	crc32Digest = "y/Q5Jg=="
	md5Digest   = "JfnnlDI7RTiF9RgfG2JNCw=="
)

func requireUploadCode(t *testing.T, err error, code string) {
	t.Helper()
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Code != code {
		t.Fatalf("upload error = %v, want %s", err, code)
	}
}

func TestUploadChecksumVectors(t *testing.T) {
	for algorithm, digest := range map[string]string{
		"crc32":     crc32Digest,
		"crc32c":    "4waSgw==",
		"crc64nvme": "rosUhgp5mIg=",
		"md5":       md5Digest,
		"sha1":      "98O8HYCOBHMq32eZZczDTKeuNEE=",
		"sha256":    "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU=",
		"sha512":    "2eZ2LdHI6vbWGzxhkvxAjU1tXxF20MKRabwk5xw/J0rSf81YEbMT1oH35V7ALXPUmclUVba1u1A6z1dPuo/+hQ==",
	} {
		r := httptest.NewRequest("PUT", "/", strings.NewReader("123456789"))
		header := checksumPrefix + algorithm
		r.Header.Set(header, digest)
		r.Header.Set(contentMD5, md5Digest)
		body, err := newUploadBody(r)
		if err != nil || body == nil {
			t.Fatalf("%s upload reader: %v, %v", algorithm, body, err)
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			t.Fatal(err)
		}
		if err := body.finish(); err != nil {
			t.Fatal(err)
		}
		h := make(http.Header)
		body.setResponseHeaders(h)
		if h.Get(header) != digest || h.Get(checksumType) != fullObject {
			t.Fatalf("%s response headers = %v", algorithm, h)
		}
	}
}

func TestInvalidUploadHeaders(t *testing.T) {
	for _, tc := range []struct {
		code    string
		headers http.Header
	}{
		{"InvalidDigest", http.Header{crc32Header: {"y/Q5Jh=="}}},
		{"InvalidDigest", http.Header{crc32Header: {"YWJjZGVm"}}},
		{"InvalidRequest", http.Header{crc32Header: {crc32Digest, crc32Digest}}},
		{"InvalidRequest", http.Header{checksumPrefix + "unknown": {crc32Digest}}},
		{"InvalidRequest", http.Header{crc32Header: {crc32Digest}, checksumType: {"COMPOSITE"}}},
		{"BadDigest", http.Header{crc32Header: {crc32Digest}, checksumAlgorithm: {"SHA256"}}},
		{"NotImplemented", http.Header{"x-amz-content-sha256": {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"}}},
	} {
		r := httptest.NewRequest("PUT", "/", nil)
		for name, values := range tc.headers {
			r.Header[http.CanonicalHeaderKey(name)] = values
		}
		_, err := newUploadBody(r)
		requireUploadCode(t, err, tc.code)
	}
}

func TestAWSChunkedFraming(t *testing.T) {
	const trailer = crc32Header + ":" + crc32Digest + "\r\n"
	const frame = "3;part=1\r\n123\r\n6 \t\r\n456789\r\n0\r\n" + trailer + "\r\n"
	check := func(framed, length string) error {
		r := httptest.NewRequest("PUT", "/", strings.NewReader(framed))
		r.Header.Set("Content-Encoding", "aws-chunked")
		r.Header.Set("x-amz-content-sha256", unsignedTrailerMode)
		r.Header.Set(awsTrailerHeader, crc32Header)
		r.Header.Set(decodedLengthHeader, length)
		body, err := newUploadBody(r)
		if err != nil || body == nil {
			t.Fatalf("aws-chunked upload reader: %v, %v", body, err)
		}
		var data [9]byte
		if _, err := io.ReadFull(body, data[:]); err != nil {
			return err
		}
		return body.finish()
	}
	if err := check(frame, "9"); err != nil {
		t.Fatal(err)
	}
	for i := range len(frame) {
		requireUploadCode(t, check(frame[:i], "9"), "InvalidRequest")
	}
	requireUploadCode(t, check(frame+trailer, "9"), "InvalidRequest")
	requireUploadCode(t, check(strings.TrimSuffix(frame, "\r\n")+trailer+"\r\n", "9"), "InvalidRequest")
	requireUploadCode(t, check(frame, "8"), "InvalidRequest")
	requireUploadCode(t, check(frame, "10"), "InvalidRequest")
	requireUploadCode(t, check(strings.Replace(frame, crc32Digest, "AAAAAA==", 1), "9"), "BadDigest")
}

func TestDirectoryUploadWithLateHTTPChecksumTrailer(t *testing.T) {
	const marker = "/marker/"
	server := &S3Server{log: log.NewLogger(os.Stderr, &log.LoggerOptions{Level: log.ERROR})}
	for _, tc := range []struct{ header, chunks string }{
		{"", "3\r\nabc\r\n"},
		{"X-Amz-Checksum-Crc32: AAAAAA==\r\n", ""},
	} {
		wire := "PUT /bucket" + marker + " HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n" +
			tc.header + "\r\n" + tc.chunks + "0\r\nContent-MD5: " + md5Digest + "\r\n\r\n"
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatal(err)
		}
		err = server.handlePutObject(r.Context(), httptest.NewRecorder(), r, "bucket", msgs.ROOT_DIR_INODE_ID, parseObjectPath(marker))
		r.Body.Close()
		requireUploadCode(t, err, "InvalidRequest")
	}
}
