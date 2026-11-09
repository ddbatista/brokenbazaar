package measure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client speaks the Anthropic Messages API over the standard library
// (TM D1). Not the SDK: its default client reads ANTHROPIC_API_KEY,
// ANTHROPIC_BASE_URL and saved profiles from the environment -- a base
// URL plus an ambient vendor key is the credential-leak primitive D1b
// forbids ("point it anywhere and the key goes along"). This client is
// handed its key and base URL explicitly, and its transport ignores the
// HTTP(S)_PROXY variables too: the key goes to the configured host and
// nowhere else.
type Client struct {
	endpoint string
	key      string
	version  string
	http     *http.Client
	sleep    func(context.Context, time.Duration) error
}

// Reply is one HTTP exchange's evidence. Headers are not kept, except
// the request id, which identifies the call to the provider.
type Reply struct {
	Status    int
	Body      []byte
	RequestID string
}

// Sender is what Run needs; the Client is one, a test fake is another.
type Sender interface {
	Send(ctx context.Context, req Request) (Reply, error)
}

const (
	attempts = 4
	maxWait  = 60 * time.Second // a retry-after beyond this is capped, not obeyed
)

// NewClient refuses an empty key or base URL, and refuses to attach the
// key to anything but HTTPS -- plain HTTP only to a loopback IP address
// (D1b requirement 2). The loopback test is on the address, not on a
// name: "localhost" is a string, and SR-B7-1's shape is a decision about
// the address, not a string match.
func NewClient(baseURL, key, version string) (*Client, error) {
	if key == "" {
		return nil, fmt.Errorf("MODEL_API_KEY is empty")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("MODEL_BASE_URL is empty -- name the destination the key is sent to")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("MODEL_BASE_URL: %w", err)
	}
	if u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("MODEL_BASE_URL must not carry credentials or a query")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("MODEL_BASE_URL: refusing to send the key over plain HTTP to %q (HTTPS, or a loopback IP)", u.Hostname())
		}
	default:
		return nil, fmt.Errorf("MODEL_BASE_URL scheme %q: want https", u.Scheme)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{
		endpoint: u.String() + "/v1/messages",
		key:      key,
		version:  version,
		http: &http.Client{
			Timeout:   10 * time.Minute,
			Transport: transport,
			// net/http forwards x-api-key across a redirect (it strips
			// only Authorization, Cookie and Proxy-*). A redirect is
			// returned as the response, never followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sleep: sleepCtx,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryable marks a failure worth another attempt, and how long to wait.
type retryable struct {
	err  error
	wait time.Duration
}

func (r *retryable) Error() string { return r.err.Error() }
func (r *retryable) Unwrap() error { return r.err }

// Send posts one request, retrying overload and transport failures a
// bounded number of times. Any other non-200 (a 4xx, a 3xx) is not
// retried: it is a broken request. On failure the last Reply is still
// returned -- status, body and request id are the evidence.
func (c *Client) Send(ctx context.Context, req Request) (Reply, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Reply{}, err
	}
	var last Reply
	var lastErr error
	for i := 0; i < attempts; i++ {
		r, err := c.once(ctx, body)
		if err == nil {
			return r, nil
		}
		last, lastErr = r, err
		var rt *retryable
		if !errors.As(err, &rt) {
			return r, err
		}
		if i == attempts-1 {
			break
		}
		if serr := c.sleep(ctx, min(rt.wait, maxWait)); serr != nil {
			return r, serr
		}
	}
	return last, fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

func (c *Client) once(ctx context.Context, body []byte) (Reply, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Reply{}, err
	}
	hreq.Header.Set("content-type", "application/json")
	hreq.Header.Set("x-api-key", c.key)
	hreq.Header.Set("anthropic-version", c.version)

	resp, err := c.http.Do(hreq)
	if err != nil {
		if ctx.Err() != nil {
			return Reply{}, ctx.Err()
		}
		return Reply{}, &retryable{err: fmt.Errorf("transport: %s", c.scrub(err.Error())), wait: 2 * time.Second}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Reply{}, &retryable{err: fmt.Errorf("reading response: %w", err), wait: 2 * time.Second}
	}
	r := Reply{Status: resp.StatusCode, Body: data, RequestID: resp.Header.Get("request-id")}
	if resp.StatusCode == http.StatusOK {
		return r, nil
	}
	// Scrub BEFORE truncating: a key cut in half at the truncation point
	// would no longer match the full-key scrub.
	apiErr := fmt.Errorf("API %d: %s", resp.StatusCode, truncate(c.scrub(string(data)), 300))
	switch resp.StatusCode {
	case 429, 500, 502, 503, 504, 529:
		wait := 5 * time.Second
		if s, err := strconv.Atoi(resp.Header.Get("retry-after")); err == nil && s > 0 {
			wait = time.Duration(s) * time.Second
		}
		return r, &retryable{err: apiErr, wait: wait}
	}
	return r, apiErr
}

// scrub replaces the key wherever it appears in text bound for an error.
func (c *Client) scrub(s string) string { return strings.ReplaceAll(s, c.key, "[MODEL_API_KEY]") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// IsRejected reports a non-retryable HTTP rejection (a 3xx or a 4xx other
// than 429): the request itself is broken, so the run cannot continue.
func IsRejected(r Reply) bool {
	return r.Status >= 300 && r.Status < 500 && r.Status != 429
}
