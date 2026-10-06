// Package hush reads the Hush API with an API key.
package hush

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	tokenPath = "/v1/oauth/token"
	// Renew a token this long before it expires.
	tokenMargin = 30 * time.Second
	pageSize    = 100
)

// Client calls the Hush API, exchanging its API key for short-lived tokens.
type Client struct {
	baseURL string
	keyID   string
	secret  string
	http    *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// BaseURL returns the API of a Hush realm, e.g. "US" or "EU".
func BaseURL(realm string) string {
	return fmt.Sprintf("https://api.%s.hush-security.com", strings.ToLower(realm))
}

func NewClient(baseURL, keyID, secret string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		keyID:   keyID,
		secret:  secret,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// APIError is a non-2xx answer from the Hush API.
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > tokenMargin {
		return c.token, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.keyID, c.secret)

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := c.send(req, &tok); err != nil {
		return "", fmt.Errorf("get a token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("get a token: empty access_token")
	}
	c.token = tok.AccessToken
	c.expires = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req, out)
}

func (c *Client) send(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(data))}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decode: %w", req.Method, req.URL.Path, err)
	}
	return nil
}

// page is hush.pagination.CursorPage.
type page[T any] struct {
	Items    []T     `json:"items"`
	NextPage *string `json:"next_page"`
}

// getAll follows a GET list endpoint's `cursor` query parameter.
func getAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	cursor := ""
	for {
		p := path
		if cursor != "" {
			sep := "?"
			if strings.Contains(p, "?") {
				sep = "&"
			}
			p += sep + "cursor=" + url.QueryEscape(cursor)
		}
		var resp page[T]
		if err := c.do(ctx, http.MethodGet, p, nil, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Items...)
		if resp.NextPage == nil || *resp.NextPage == "" {
			return all, nil
		}
		cursor = *resp.NextPage
	}
}

// Filter is one of apollo's list filters.
type Filter struct {
	Name   string   `json:"name"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

type findingsRequest struct {
	Filters    []Filter `json:"filters"`
	Pagination bool     `json:"pagination"`
	Page       *string  `json:"page,omitempty"`
	PageSize   int      `json:"page_size"`
}

// postAll follows a POST findings endpoint, whose cursor travels in the body.
func postAll[T any](ctx context.Context, c *Client, path string, filters []Filter) ([]T, error) {
	var all []T
	req := findingsRequest{Filters: filters, Pagination: true, PageSize: pageSize}
	for {
		var resp page[T]
		if err := c.do(ctx, http.MethodPost, path, req, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Items...)
		if resp.NextPage == nil || *resp.NextPage == "" {
			return all, nil
		}
		req.Page = resp.NextPage
	}
}
