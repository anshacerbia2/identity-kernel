// Package admin is a minimal client for the Keycloak Admin REST API: the one surface through which
// this repository reads and changes a live realm. TDD-identity-kernel-001 requires configuration to
// go through the supported Admin API rather than a realm import, and ADR-IAM-001 §5.7 prohibits
// authoring it in the Admin Console, so everything that touches a realm goes through here.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Credentials select how the client obtains an administrator token in the master realm: a
// service account's client id and secret, or the bootstrap administrator's username and password.
// The second exists for local and throwaway instances; a long-lived server should be administered
// through a service account whose secret can be rotated without touching a person's login.
type Credentials struct {
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
}

// Client calls one Keycloak's Admin API.
type Client struct {
	base  string
	http  *http.Client
	creds Credentials
}

// New validates the configuration before anything is sent, so a missing credential is a
// configuration error rather than a 401 read as a permission problem.
func New(base string, httpClient *http.Client, creds Credentials) (*Client, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	parsed, err := url.Parse(base)
	if base == "" || err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("admin: %q is not a Keycloak base URL", base)
	}
	switch {
	case creds.ClientID != "" && creds.ClientSecret != "":
	case creds.ClientID == "" && creds.Username != "" && creds.Password != "":
	default:
		return nil, errors.New("admin: credentials need a client id and secret, or a username and password")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{base: base, http: httpClient, creds: creds}, nil
}

// Base is the Keycloak base URL, without a trailing slash.
func (c *Client) Base() string { return c.base }

// HTTP is the underlying client, for callers that talk to the protocol endpoints directly.
func (c *Client) HTTP() *http.Client { return c.http }

// Response is an Admin API answer with its body already read.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// CreatedID returns the identifier Keycloak put in the Location header of a 201.
func (r *Response) CreatedID() string {
	location := r.Header.Get("Location")
	return location[strings.LastIndex(location, "/")+1:]
}

// StatusError is an answer other than the one the caller required.
type StatusError struct {
	Method, Path string
	Status, Want int
	Body         string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("admin: %s %s answered %d, want %d: %s", e.Method, e.Path, e.Status, e.Want, e.Body)
}

// IsNotFound reports whether err is a 404 from the Admin API.
func IsNotFound(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Status == http.StatusNotFound
}

// Call sends one request and requires the status want. The response is returned alongside a
// StatusError too, because what Keycloak answered is sometimes the thing being asked.
func (c *Client) Call(ctx context.Context, method, path string, body any, want int) (*Response, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	case json.RawMessage:
		reader = bytes.NewReader(b)
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			return nil, fmt.Errorf("admin: encoding the %s %s body: %w", method, path, err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, fmt.Errorf("admin: %s %s: %w", method, path, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if reader != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("admin: %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("admin: reading the %s %s answer: %w", method, path, err)
	}
	out := &Response{Status: response.StatusCode, Header: response.Header, Body: raw}
	if response.StatusCode != want {
		return out, &StatusError{Method: method, Path: path, Status: response.StatusCode, Want: want,
			Body: truncate(string(raw))}
	}
	return out, nil
}

// GetJSON reads one resource into into.
func (c *Client) GetJSON(ctx context.Context, path string, into any) error {
	response, err := c.Call(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(response.Body, into); err != nil {
		return fmt.Errorf("admin: decoding GET %s: %w", path, err)
	}
	return nil
}

// token is fetched per call. Admin tokens live for a minute by default and nothing here issues
// enough calls for a cache to pay for its failure mode: a token that expired between two calls.
func (c *Client) token(ctx context.Context) (string, error) {
	form := url.Values{}
	if c.creds.ClientID != "" {
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", c.creds.ClientID)
		form.Set("client_secret", c.creds.ClientSecret)
	} else {
		form.Set("grant_type", "password")
		form.Set("client_id", "admin-cli")
		form.Set("username", c.creds.Username)
		form.Set("password", c.creds.Password)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("admin: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("admin: reaching Keycloak at %s: %w", c.base, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		// The token endpoint's error body names the error class, never the credential, so it is
		// safe to repeat and it is the one thing that tells a wrong secret from a wrong URL.
		return "", fmt.Errorf("admin: the master realm refused the administrator login with %d: %s",
			response.StatusCode, truncate(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("admin: the master realm returned no access token")
	}
	return out.AccessToken, nil
}

func truncate(s string) string {
	const limit = 512
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
