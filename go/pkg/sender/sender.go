package sender

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"interview/pkg/dto"
)

// Send dispatches every attack request to baseURL using a bounded worker pool of
// size `concurrency`, so the target is never hit with more than N requests in
// flight — the safety valve that keeps us from overloading a customer's API.
// The returned responses are index-aligned with the input attacks.
func Send(attacks []dto.AttackRequest, baseURL string, concurrency int) []dto.Response {
	if concurrency < 1 {
		concurrency = 1
	}

	responses := make([]dto.Response, len(attacks))
	sem := make(chan struct{}, concurrency)
	client := &http.Client{Timeout: 10 * time.Second}
	var wg sync.WaitGroup

	for i, a := range attacks {
		wg.Add(1)
		sem <- struct{}{} // acquire a slot (blocks when `concurrency` are in flight)
		go func(i int, a dto.AttackRequest) {
			defer wg.Done()
			defer func() { <-sem }() // release the slot
			responses[i] = do(client, baseURL, a.Request)
		}(i, a)
	}

	wg.Wait()
	return responses
}

func do(client *http.Client, baseURL string, r dto.Request) dto.Response {
	u := baseURL + r.RenderedPath()
	if len(r.Query) > 0 {
		q := url.Values{}
		for k, v := range r.Query {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}

	var body io.Reader
	if len(r.Body) > 0 {
		if b, err := json.Marshal(r.Body); err == nil {
			body = bytes.NewReader(b)
		}
	}

	req, err := http.NewRequest(r.Method, u, body)
	if err != nil {
		return dto.Response{Status: 0, Body: "request build error: " + err.Error()}
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return dto.Response{Status: 0, Body: "transport error: " + err.Error()}
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return dto.Response{Status: resp.StatusCode, Body: string(data)}
}
