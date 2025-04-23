package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/slashlight/mitmProxy/pkg/storage"
)

func ScanForSQLInjection(req *storage.Request, resp *storage.Response) []storage.SQLInjectionResult {
	var results []storage.SQLInjectionResult

	payloads := []string{"'", "\""}

	for name, value := range req.GetParams {
		for _, payload := range payloads {
			testReq := *req
			testReq.GetParams[name] = payload

			testResp, err := sendTestRequest(&testReq)
			if err != nil {
				continue
			}

			result := storage.SQLInjectionResult{
				ParameterType: "GET",
				ParameterName: name,
				Payload:       payload,
				OriginalCode:  resp.StatusCode,
				OriginalLen:   len(resp.Body),
				TestCode:      testResp.StatusCode,
				TestLen:       len(testResp.Body),
			}

			result.IsVulnerable = isVulnerable(resp, testResp)
			if result.IsVulnerable {
				results = append(results, result)
			}
		}
	}

	for name, value := range req.PostParams {
		for _, payload := range payloads {
			testReq := *req
			testReq.PostParams[name] = payload

			testResp, err := sendTestRequest(&testReq)
			if err != nil {
				continue
			}

			result := storage.SQLInjectionResult{
				ParameterType: "POST",
				ParameterName: name,
				Payload:       payload,
				OriginalCode:  resp.StatusCode,
				OriginalLen:   len(resp.Body),
				TestCode:      testResp.StatusCode,
				TestLen:       len(testResp.Body),
			}

			result.IsVulnerable = isVulnerable(resp, testResp)
			if result.IsVulnerable {
				results = append(results, result)
			}
		}
	}

	for name, value := range req.Cookies {
		for _, payload := range payloads {
			testReq := *req
			testReq.Cookies[name] = payload

			testResp, err := sendTestRequest(&testReq)
			if err != nil {
				continue
			}

			result := storage.SQLInjectionResult{
				ParameterType: "Cookie",
				ParameterName: name,
				Payload:       payload,
				OriginalCode:  resp.StatusCode,
				OriginalLen:   len(resp.Body),
				TestCode:      testResp.StatusCode,
				TestLen:       len(testResp.Body),
			}

			result.IsVulnerable = isVulnerable(resp, testResp)
			if result.IsVulnerable {
				results = append(results, result)
			}
		}
	}

	for name, value := range req.Headers {
		if strings.ToLower(name) == "host" || strings.ToLower(name) == "content-length" {
			continue
		}

		for _, payload := range payloads {
			testReq := *req
			testReq.Headers[name] = payload

			testResp, err := sendTestRequest(&testReq)
			if err != nil {
				continue
			}

			result := storage.SQLInjectionResult{
				ParameterType: "Header",
				ParameterName: name,
				Payload:       payload,
				OriginalCode:  resp.StatusCode,
				OriginalLen:   len(resp.Body),
				TestCode:      testResp.StatusCode,
				TestLen:       len(testResp.Body),
			}

			result.IsVulnerable = isVulnerable(resp, testResp)
			if result.IsVulnerable {
				results = append(results, result)
			}
		}
	}

	return results
}

func sendTestRequest(req *storage.Request) (*storage.Response, error) {
	client := &http.Client{}

	urlStr := fmt.Sprintf("http://%s%s", req.Headers["Host"], req.Path)
	if len(req.GetParams) > 0 {
		params := url.Values{}
		for k, v := range req.GetParams {
			params.Add(k, v)
		}
		urlStr += "?" + params.Encode()
	}

	httpReq, err := http.NewRequest(req.Method, urlStr, strings.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	return &storage.Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
	}, nil
}

func isVulnerable(originalResp, testResp *storage.Response) bool {
	if originalResp.StatusCode != testResp.StatusCode {
		return true
	}

	originalLen := len(originalResp.Body)
	testLen := len(testResp.Body)
	if originalLen > 0 {
		diff := float64(abs(originalLen-testLen)) / float64(originalLen)
		if diff > 0.1 {
			return true
		}
	}

	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
