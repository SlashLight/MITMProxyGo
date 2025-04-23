package parser

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/slashlight/mitmProxy/pkg/storage"
)

func ParseRequest(req *http.Request) (*storage.Request, error) {

	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	getParams := make(map[string]string)
	for k, v := range parsedURL.Query() {
		if len(v) > 0 {
			getParams[k] = v[0]
		}
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, ", ")
	}

	cookies := make(map[string]string)
	for _, cookie := range req.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	postParams := make(map[string]string)
	if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err == nil {
			for k, v := range values {
				if len(v) > 0 {
					postParams[k] = v[0]
				}
			}
		}
	}

	return &storage.Request{
		Method:     req.Method,
		Path:       parsedURL.Path,
		GetParams:  getParams,
		Headers:    headers,
		Cookies:    cookies,
		PostParams: postParams,
		Body:       string(body),
	}, nil
}

func ParseResponse(resp *http.Response) (*storage.Response, error) {

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	var body []byte
	var err error

	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer reader.Close()
		body, err = io.ReadAll(reader)
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return &storage.Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
	}, nil
}
