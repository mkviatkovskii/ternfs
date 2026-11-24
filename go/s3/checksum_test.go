// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package s3

import (
	"encoding/base64"
	"encoding/xml"
	"hash/crc32"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/XTXMarkets/ternfs/go/client"
	"github.com/XTXMarkets/ternfs/go/core/crc32c"
	"github.com/XTXMarkets/ternfs/go/core/log"
	"github.com/XTXMarkets/ternfs/go/msgs"
)

func TestFullObjectCRC32C(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
	}{
		{"empty", nil},
		{"single", []string{"bazzer\n"}},
		{"multiple", []string{"first", strings.Repeat("\x00", 4097), "z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var size uint64
			var spans []client.SpanWithBlockServices
			want := crc32.New(crc32.MakeTable(crc32.Castagnoli))
			for _, part := range tc.parts {
				data := []byte(part)
				header := msgs.FetchedSpanHeader{
					ByteOffset: size,
					Size:       uint32(len(data)),
					Crc:        msgs.Crc(crc32c.Sum(0, data)),
				}
				spans = append(spans, client.SpanWithBlockServices{
					Span: &msgs.FetchedSpan{Header: header},
				})
				size += uint64(len(data))
				want.Write(data)
			}
			got, err := fullObjectCRC32C(spans, size)
			if err != nil {
				t.Fatal(err)
			}
			if encoded := base64.StdEncoding.EncodeToString(want.Sum(nil)); got != encoded {
				t.Errorf("full CRC32C = %q, want %q", got, encoded)
			}
		})
	}
}

func TestFullObjectCRC32CInvalidCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    uint64
		headers []msgs.FetchedSpanHeader
	}{
		{"missing", 3, nil},
		{"short", 4, []msgs.FetchedSpanHeader{{Size: 3}}},
		{"long", 2, []msgs.FetchedSpanHeader{{Size: 3}}},
		{"zero length", 0, []msgs.FetchedSpanHeader{{}}},
		{"gap", 4, []msgs.FetchedSpanHeader{{Size: 2}, {ByteOffset: 3, Size: 1}}},
		{"overlap", 4, []msgs.FetchedSpanHeader{{Size: 2}, {ByteOffset: 1, Size: 2}}},
		{"reversed", 2, []msgs.FetchedSpanHeader{{ByteOffset: 1, Size: 1}, {Size: 1}}},
		{"offset wraps", 1, []msgs.FetchedSpanHeader{{ByteOffset: math.MaxUint64, Size: 2}}},
		{"size truncated", 1<<32 + 1, []msgs.FetchedSpanHeader{{Size: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var spans []client.SpanWithBlockServices
			for _, header := range tc.headers {
				spans = append(spans, client.SpanWithBlockServices{
					Span: &msgs.FetchedSpan{Header: header},
				})
			}
			if got, err := fullObjectCRC32C(spans, tc.size); got != "" || err == nil {
				t.Errorf("full CRC32C = %q, error = %v", got, err)
			}
		})
	}
}

func TestGetObjectInvalidChecksumMode(t *testing.T) {
	logger := log.NewLogger(os.Stderr, &log.LoggerOptions{Level: log.ERROR})
	s := NewS3Server(logger, nil, nil, nil, map[string]string{"bucket": "/"}, "")
	for _, tc := range []struct {
		method string
		modes  []string
	}{
		{http.MethodHead, []string{"OTHER"}},
		{http.MethodGet, []string{"ENABLED", "OTHER"}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/bucket/key", nil)
			for _, mode := range tc.modes {
				req.Header.Add("x-amz-checksum-mode", mode)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			resp := w.Result()
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if resp.Header.Get("x-amz-checksum-crc32c") != "" || resp.Header.Get("x-amz-checksum-type") != "" {
				t.Errorf("unexpected checksum headers on error: %v", resp.Header)
			}
			if tc.method == http.MethodGet {
				var response S3Error
				if err := xml.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatal(err)
				}
				if response.Code != "InvalidArgument" {
					t.Errorf("S3 error = %q, want InvalidArgument", response.Code)
				}
			}
		})
	}
}
