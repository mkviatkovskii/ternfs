// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"time"

	"github.com/XTXMarkets/ternfs/go/client"
	"github.com/XTXMarkets/ternfs/go/core/bufpool"
	"github.com/XTXMarkets/ternfs/go/core/log"
	"github.com/XTXMarkets/ternfs/go/core/wyhash"
	"github.com/XTXMarkets/ternfs/go/msgs"
	terns3 "github.com/XTXMarkets/ternfs/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func s3ChecksumModeTest(log *log.Logger, registryAddress string, counters *client.ClientCounters) {
	c := newTestClient(log, registryAddress, counters)
	defer c.Close()
	bufPool := bufpool.NewBufPool()
	dirInfoCache := client.NewDirInfoCache()
	const bucket = "bucket"
	server := httptest.NewServer(terns3.NewS3Server(
		log, c, bufPool, dirInfoCache, map[string]string{bucket: "/"}, "",
	))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 90 * time.Second
	s3Client := s3.New(s3.Options{
		BaseEndpoint:               aws.String(server.URL),
		Credentials:                aws.AnonymousCredentials{},
		HTTPClient:                 httpClient,
		Region:                     "us-east-1",
		UsePathStyle:               true,
		Retryer:                    aws.NopRetryer{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	ctx := context.Background()

	const spanSize = msgs.TERN_PAGE_SIZE
	const seed = 42
	const multiSpanKey = "native-multi-span"
	multiSpanData := make([]byte, int(spanSize)+16)
	wyhash.New(seed).Read(multiSpanData)
	castagnoli := crc32.MakeTable(crc32.Castagnoli)
	checksum := func(data []byte) string {
		var crc [4]byte
		binary.BigEndian.PutUint32(crc[:], crc32.Checksum(data, castagnoli))
		return base64.StdEncoding.EncodeToString(crc[:])
	}

	for _, fixture := range []struct {
		key  string
		data []byte
		crc  string
	}{
		{"native-empty", nil, "AAAAAA=="},
		{"native-single-span", multiSpanData[:32], checksum(multiSpanData[:32])},
		{multiSpanKey, multiSpanData, checksum(multiSpanData)},
	} {
		createFile(log, c, dirInfoCache, msgs.ROOT_DIR_INODE_ID,
			spanSize, fixture.key, uint64(len(fixture.data)), seed, bufPool)

		for _, mode := range []types.ChecksumMode{"", types.ChecksumModeEnabled} {
			head, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(bucket), Key: aws.String(fixture.key), ChecksumMode: mode,
			})
			if err != nil {
				panic(fmt.Errorf("HEAD %s with checksum mode %q: %w", fixture.key, mode, err))
			}
			if aws.ToInt64(head.ContentLength) != int64(len(fixture.data)) {
				panic(fmt.Errorf("HEAD %s with checksum mode %q: length got %d, want %d",
					fixture.key, mode, aws.ToInt64(head.ContentLength), len(fixture.data)))
			}
			if mode == "" {
				if head.ChecksumCRC32C != nil || head.ChecksumType != "" {
					panic(fmt.Errorf("plain HEAD %s returned checksum %q and type %q",
						fixture.key, aws.ToString(head.ChecksumCRC32C), head.ChecksumType))
				}
			} else if aws.ToString(head.ChecksumCRC32C) != fixture.crc ||
				head.ChecksumType != types.ChecksumTypeFullObject {
				panic(fmt.Errorf("checksum-enabled HEAD %s: got %q (%q), want %q (FULL_OBJECT)",
					fixture.key, aws.ToString(head.ChecksumCRC32C), head.ChecksumType, fixture.crc))
			}
		}

		get, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(fixture.key),
			ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			panic(fmt.Errorf("checksum-enabled GET %s: %w", fixture.key, err))
		}
		body, err := io.ReadAll(get.Body)
		get.Body.Close()
		if err != nil {
			panic(fmt.Errorf("read GET body for %s: %w", fixture.key, err))
		}
		if !bytes.Equal(body, fixture.data) {
			panic(fmt.Errorf("GET %s: body differs from the native fixture", fixture.key))
		}
		if aws.ToString(get.ChecksumCRC32C) != fixture.crc ||
			get.ChecksumType != types.ChecksumTypeFullObject {
			panic(fmt.Errorf("checksum-enabled GET %s: got %q (%q), want %q (FULL_OBJECT)",
				fixture.key, aws.ToString(get.ChecksumCRC32C), get.ChecksumType, fixture.crc))
		}
	}

	start, end := int(spanSize)-2, int(spanSize)+2
	byteRange := fmt.Sprintf("bytes=%d-%d", start, end)
	contentRange := fmt.Sprintf("bytes %d-%d/%d", start, end, len(multiSpanData))
	for _, tc := range []struct {
		name         string
		method       string
		key          string
		mode         string
		byteRange    string
		status       int
		contentRange string
		crc          []string
		checksumType []string
		body         []byte
	}{
		{
			name: "ranged GET", method: http.MethodGet, key: multiSpanKey,
			mode: "ENABLED", byteRange: byteRange, status: http.StatusPartialContent,
			contentRange: contentRange, body: multiSpanData[start : end+1],
		},
		{
			name: "ranged HEAD", method: http.MethodHead, key: multiSpanKey,
			mode: "ENABLED", byteRange: byteRange, status: http.StatusPartialContent,
			contentRange: contentRange, crc: []string{checksum(multiSpanData)},
			checksumType: []string{"FULL_OBJECT"},
		},
		{
			name: "invalid mode", method: http.MethodGet, key: multiSpanKey,
			mode: "DISABLED", status: http.StatusBadRequest,
		},
		{
			name: "unsatisfiable range", method: http.MethodGet, key: multiSpanKey,
			mode: "ENABLED", byteRange: "bytes=99999-",
			status:       http.StatusRequestedRangeNotSatisfiable,
			contentRange: fmt.Sprintf("bytes */%d", len(multiSpanData)),
		},
		{
			name: "missing key", method: http.MethodGet, key: "native-missing",
			mode: "ENABLED", status: http.StatusNotFound,
		},
	} {
		req, err := http.NewRequest(tc.method, server.URL+"/"+bucket+"/"+tc.key, nil)
		if err != nil {
			panic(err)
		}
		req.Header.Set("x-amz-checksum-mode", tc.mode)
		if tc.byteRange != "" {
			req.Header.Set("Range", tc.byteRange)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			panic(fmt.Errorf("%s: %w", tc.name, err))
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			panic(fmt.Errorf("%s: read response: %w", tc.name, err))
		}
		if resp.StatusCode != tc.status {
			panic(fmt.Errorf("%s: status got %d, want %d", tc.name, resp.StatusCode, tc.status))
		}
		if got := resp.Header.Get("Content-Range"); got != tc.contentRange {
			panic(fmt.Errorf("%s: Content-Range got %q, want %q", tc.name, got, tc.contentRange))
		}
		if tc.status == http.StatusPartialContent && resp.ContentLength != int64(end-start+1) {
			panic(fmt.Errorf("%s: length got %d, want %d", tc.name, resp.ContentLength, end-start+1))
		}
		if got := resp.Header.Values("x-amz-checksum-crc32c"); !slices.Equal(got, tc.crc) {
			panic(fmt.Errorf("%s: checksum got %q, want %q", tc.name, got, tc.crc))
		}
		if got := resp.Header.Values("x-amz-checksum-type"); !slices.Equal(got, tc.checksumType) {
			panic(fmt.Errorf("%s: checksum type got %q, want %q", tc.name, got, tc.checksumType))
		}
		if tc.status >= http.StatusBadRequest {
			var s3Err terns3.S3Error
			if err := xml.Unmarshal(body, &s3Err); err != nil || s3Err.Code == "" {
				panic(fmt.Errorf("%s: expected S3 error, got %q (decode error %v)", tc.name, body, err))
			}
		} else if !bytes.Equal(body, tc.body) {
			panic(fmt.Errorf("%s: body got %q, want %q", tc.name, body, tc.body))
		}
	}
}
