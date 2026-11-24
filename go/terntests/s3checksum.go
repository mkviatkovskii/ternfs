// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/XTXMarkets/ternfs/go/client"
	"github.com/XTXMarkets/ternfs/go/core/bufpool"
	"github.com/XTXMarkets/ternfs/go/core/log"
	terns3 "github.com/XTXMarkets/ternfs/go/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func s3ChecksumTest(log *log.Logger, registryAddress string, counters *client.ClientCounters) {
	const bucket, knownKey = "bucket", "checksum-known"
	const checksumHeader = "x-amz-checksum-sha256"
	payload := strings.Repeat("valid streaming upload\n", 4096)
	length := int64(len(payload))
	sum := sha256.Sum256([]byte(payload))
	digest := base64.StdEncoding.EncodeToString(sum[:])
	c := newTestClient(log, registryAddress, counters)
	defer c.Close()
	handler := terns3.NewS3Server(log, c, bufpool.NewBufPool(), client.NewDirInfoCache(),
		map[string]string{bucket: "/"}, "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantLength := ""
		if r.URL.Path == "/"+bucket+"/"+knownKey {
			wantLength = fmt.Sprint(length)
		}
		h := r.Header
		if h.Get("X-Amz-Content-Sha256") != "STREAMING-UNSIGNED-PAYLOAD-TRAILER" ||
			h.Get("Content-Encoding") != "aws-chunked" || h.Get("X-Amz-Trailer") != checksumHeader ||
			h.Get(checksumHeader) != "" || h.Get("X-Amz-Decoded-Content-Length") != wantLength {
			http.Error(w, "unexpected SDK streaming headers", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	sdk := s3.New(s3.Options{
		BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Region:      "us-east-1", UsePathStyle: true,
	})

	request := func(method, key, wire string, status int, code string) *httptest.ResponseRecorder {
		message := method + " /" + bucket + "/" + key + " HTTP/1.1\r\nHost: test\r\n" + wire
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(message)))
		if err != nil {
			panic(err)
		}
		defer req.Body.Close()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != status || (code != "" && !strings.Contains(w.Body.String(), "<Code>"+code+"</Code>")) {
			panic(fmt.Errorf("%s %s: got HTTP %d %.200q, want %d %s", method, key, w.Code, w.Body.String(), status, code))
		}
		return w
	}
	etags := make(map[string]string)
	for key, contentLength := range map[string]*int64{knownKey: &length, "checksum-unknown": nil} {
		result, err := sdk.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(key),
			Body: io.LimitReader(strings.NewReader(payload), length), ContentLength: contentLength,
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		})
		if err != nil {
			panic(err)
		}
		if aws.ToString(result.ChecksumSHA256) != digest || result.ChecksumType != types.ChecksumTypeFullObject {
			panic(fmt.Errorf("PUT %s: unexpected checksum response", key))
		}
		etags[key] = aws.ToString(result.ETag)
	}

	bad := checksumHeader + ": " + digest + "\r\nContent-Length: 1\r\n\r\nx"
	request("PUT", "checksum-missing", bad, 400, "BadDigest")
	request("PUT", knownKey, bad, 400, "BadDigest")
	request("PUT", "checksum-marker/", checksumHeader+": "+digest+"\r\n\r\n", 400, "BadDigest")
	request("PUT", "checksum-marker/", bad, 400, "InvalidRequest")
	request("GET", "checksum-missing", "\r\n", 404, "NoSuchKey")
	request("GET", "checksum-marker/", "\r\n", 404, "NoSuchKey")
	sumX := sha256.Sum256([]byte("x"))
	trailer := checksumHeader + ": " + base64.StdEncoding.EncodeToString(sumX[:]) + "\r\n"
	for _, header := range []string{"", trailer} {
		wire := "Transfer-Encoding: chunked\r\n" + header + "\r\n1\r\nx\r\n0\r\n" + trailer + "\r\n"
		request("PUT", knownKey, wire, 400, "InvalidRequest")
	}
	for key, etag := range etags {
		w := request("GET", key, "\r\n", 200, "")
		if w.Body.String() != payload || etag == "" || w.Header().Get("ETag") != etag {
			panic(fmt.Errorf("GET %s: unexpected payload or ETag", key))
		}
	}
}
