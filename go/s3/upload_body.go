// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package s3

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
)

const (
	checksumPrefix      = "x-amz-checksum-"
	checksumType        = checksumPrefix + "type"
	checksumAlgorithm   = "x-amz-sdk-checksum-algorithm"
	fullObject          = "FULL_OBJECT"
	contentMD5          = "Content-MD5"
	unsignedTrailerMode = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	decodedLengthHeader = "x-amz-decoded-content-length"
	awsTrailerHeader    = "x-amz-trailer"
)

var crc64NVMeTable = crc64.MakeTable(0x9a6c9329ac4bc9b5)

var uploadHashes = map[string]func() hash.Hash{
	checksumPrefix + "crc32":     func() hash.Hash { return crc32.NewIEEE() },
	checksumPrefix + "crc32c":    func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) },
	checksumPrefix + "crc64nvme": func() hash.Hash { return crc64.New(crc64NVMeTable) },
	checksumPrefix + "sha1":      sha1.New,
	checksumPrefix + "sha256":    sha256.New,
	checksumPrefix + "sha512":    sha512.New,
	checksumPrefix + "md5":       md5.New,
	contentMD5:                   md5.New,
}

type uploadChecksum struct {
	hash.Hash
	header, digest string
}

func (c uploadChecksum) validateDigest() error {
	if len(c.digest) == base64.StdEncoding.EncodedLen(c.Size()) {
		digest, err := base64.StdEncoding.DecodeString(c.digest)
		if err == nil && len(digest) == c.Size() && base64.StdEncoding.EncodeToString(digest) == c.digest {
			return nil
		}
	}
	return uploadError("InvalidDigest", "Invalid digest in "+c.header)
}

type uploadBody struct {
	reader    io.Reader
	chunked   *bufio.Reader
	checksum  uploadChecksum
	legacy    uploadChecksum
	remaining int64
	readErr   error
}

func uploadError(code, message string) *S3Error {
	return &S3Error{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}

func invalidUpload(message string) *S3Error {
	return uploadError("InvalidRequest", message)
}

func newUploadBody(r *http.Request) (*uploadBody, error) {
	if err := rejectHTTPChecksumTrailers(r); err != nil {
		return nil, err
	}
	b := &uploadBody{reader: r.Body, remaining: r.ContentLength}
	if err := b.enableAWSChunks(r.Header); err != nil {
		return nil, err
	}
	for name, values := range r.Header {
		header := strings.ToLower(name)
		c := &b.checksum
		switch {
		case header == "content-md5":
			c, header = &b.legacy, contentMD5
		case header == checksumType || !strings.HasPrefix(header, checksumPrefix):
			continue
		}
		if c.header != "" || len(values) != 1 {
			return nil, invalidUpload("Expected one checksum value per source.")
		}
		c.header, c.digest = header, values[0]
	}
	for _, c := range []*uploadChecksum{&b.legacy, &b.checksum} {
		if c.header == "" {
			continue
		}
		newHash := uploadHashes[c.header]
		if newHash == nil {
			return nil, invalidUpload("Unsupported upload checksum header: " + c.header)
		}
		c.Hash = newHash()
		if c == &b.legacy || b.chunked == nil {
			if err := c.validateDigest(); err != nil {
				return nil, err
			}
		}
	}
	if values := r.Header.Values(checksumAlgorithm); len(values) != 0 {
		if len(values) != 1 || b.checksum.Hash == nil {
			return nil, invalidUpload("Expected a checksum value for " + checksumAlgorithm)
		}
		if b.checksum.header != checksumPrefix+strings.ToLower(values[0]) {
			return nil, uploadError("BadDigest", "The upload checksum does not match "+checksumAlgorithm)
		}
	}
	if values := r.Header.Values(checksumType); len(values) != 0 &&
		(len(values) != 1 || values[0] != fullObject || b.checksum.Hash == nil) {
		return nil, invalidUpload("Expected a full-object checksum.")
	}
	if b.legacy.Hash != nil && b.checksum.header == checksumPrefix+"md5" {
		b.checksum.Hash = b.legacy.Hash
	}
	if b.checksum.Hash == nil && b.legacy.Hash == nil {
		return nil, nil
	}
	return b, nil
}

func (b *uploadBody) enableAWSChunks(h http.Header) error {
	encodings := 0
	encodingHeader := strings.Join(h.Values("Content-Encoding"), ",")
	for encoding := range strings.SplitSeq(encodingHeader, ",") {
		if strings.EqualFold(strings.TrimSpace(encoding), "aws-chunked") {
			encodings++
		}
	}
	modes := h.Values("x-amz-content-sha256")
	streaming := false
	for _, mode := range modes {
		streaming = streaming || strings.HasPrefix(strings.ToUpper(mode), "STREAMING-")
	}
	trailers, lengths := h.Values(awsTrailerHeader), h.Values(decodedLengthHeader)
	if encodings == 0 && !streaming && len(trailers) == 0 && len(lengths) == 0 {
		return nil
	}
	if len(modes) == 1 && streaming && modes[0] != unsignedTrailerMode {
		return &S3Error{Code: "NotImplemented", Message: "Unsupported streaming mode.", StatusCode: http.StatusNotImplemented}
	}
	if encodings != 1 || len(modes) != 1 || modes[0] != unsignedTrailerMode ||
		len(trailers) != 1 || trailers[0] == "" {
		return invalidUpload("Invalid aws-chunked upload headers.")
	}
	b.remaining = -1
	if len(lengths) != 0 {
		length, err := strconv.ParseUint(lengths[0], 10, 63)
		if len(lengths) != 1 || err != nil {
			return invalidUpload("Invalid " + decodedLengthHeader)
		}
		b.remaining = int64(length)
	}
	b.checksum.header = strings.ToLower(trailers[0])
	b.chunked = bufio.NewReader(b.reader)
	b.reader = httputil.NewChunkedReader(b.chunked)
	return nil
}

func rejectHTTPChecksumTrailers(r *http.Request) error {
	for name := range r.Trailer {
		if isUploadChecksumTrailer(name) {
			return invalidUpload("HTTP checksum trailers are unsupported.")
		}
	}
	trailer := strings.Join(r.Header.Values("Trailer"), ",")
	for name := range strings.SplitSeq(trailer, ",") {
		if isUploadChecksumTrailer(strings.TrimSpace(name)) {
			return invalidUpload("HTTP checksum trailers are unsupported.")
		}
	}
	return nil
}

func isUploadChecksumTrailer(name string) bool {
	name = strings.ToLower(name)
	return name == "content-md5" || name == checksumAlgorithm || strings.HasPrefix(name, checksumPrefix)
}

func (b *uploadBody) Read(p []byte) (int, error) {
	if b.readErr != nil || len(p) == 0 {
		return 0, b.readErr
	}
	n, err := b.reader.Read(p)
	if b.remaining >= 0 {
		b.remaining -= int64(n)
		if b.remaining < 0 || (err == io.EOF && b.remaining != 0) {
			b.readErr = invalidUpload("The upload body does not match its declared length.")
			return 0, b.readErr
		}
	}
	switch {
	case err == io.EOF && b.chunked != nil:
		err = b.readTrailer()
	case err != nil && err != io.EOF:
		err = invalidUpload("Could not read the complete upload body.")
	}
	if b.legacy.Hash != nil {
		b.legacy.Write(p[:n])
	}
	if b.checksum.Hash != nil && b.checksum.Hash != b.legacy.Hash {
		b.checksum.Write(p[:n])
	}
	// io.ReadFull can drop an error returned with a full span.
	b.readErr = err
	return n, err
}

func (b *uploadBody) readTrailer() error {
	line, err := b.chunked.ReadSlice('\n')
	trailer, crlf := strings.CutSuffix(string(line), "\r\n")
	name, value, ok := strings.Cut(trailer, ":")
	if err != nil || !crlf || !ok || !strings.EqualFold(name, b.checksum.header) {
		return invalidUpload("Missing the declared aws-chunked checksum trailer.")
	}
	if end, err := b.chunked.Peek(3); err != io.EOF || string(end) != "\r\n" {
		return invalidUpload("Expected a blank line and the end of the aws-chunked body.")
	}
	b.checksum.digest = strings.Trim(value, " \t")
	return io.EOF
}

func (b *uploadBody) finish() error {
	var extra [1]byte
	if _, err := io.ReadFull(b, extra[:]); err == nil {
		return invalidUpload("The upload body contains unexpected object bytes.")
	} else if err != io.EOF {
		return err
	}
	for _, c := range []*uploadChecksum{&b.legacy, &b.checksum} {
		if c.Hash == nil || base64.StdEncoding.EncodeToString(c.Sum(nil)) == c.digest {
			continue
		}
		if err := c.validateDigest(); err != nil {
			return err
		}
		return uploadError("BadDigest", "The uploaded data does not match "+c.header)
	}
	return nil
}

func finishUpload(r *http.Request, body *uploadBody) error {
	if body != nil {
		if err := body.finish(); err != nil {
			return err
		}
	}
	return rejectHTTPChecksumTrailers(r)
}

func (b *uploadBody) setResponseHeaders(h http.Header) {
	if b != nil && b.checksum.Hash != nil {
		h.Set(b.checksum.header, b.checksum.digest)
		h.Set(checksumType, fullObject)
	}
}
