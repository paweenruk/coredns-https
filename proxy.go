package https

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsMessageMimeType    = "application/dns-message"
	maxDNSMessageSize     = 1472
	defaultRequestTimeout = 2 * time.Second
)

var (
	dnsMessageMimeTypeHeader = []string{dnsMessageMimeType}
	errResponseTooLarge      = errors.New("dns response size is too large")
	errResponseStatus        = errors.New("invalid http response status code")
)

type dnsClient interface {
	Query(ctx context.Context, dnsreq []byte) (*dns.Msg, error)
}

type httpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type dohDNSClient struct {
	client httpRequestDoer
	url    string
}

func newDoHDNSClient(client httpRequestDoer, url string) *dohDNSClient {
	return &dohDNSClient{client, url}
}

func (c *dohDNSClient) Query(ctx context.Context, dnsreq []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(dnsreq))
	if err != nil {
		return nil, err
	}
	req.Header["Accept"] = dnsMessageMimeTypeHeader
	req.Header["Content-Type"] = dnsMessageMimeTypeHeader

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer dumpRemainingResponse(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errResponseStatus
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDNSMessageSize {
		return nil, errResponseTooLarge
	}

	r := new(dns.Msg)
	err = r.Unpack(body)
	return r, err
}

func dumpRemainingResponse(res *http.Response) {
	if res != nil {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
}

type metricDNSClient struct {
	client dnsClient
	addr   string
}

func newMetricDNSClient(client dnsClient, addr string) *metricDNSClient {
	return &metricDNSClient{client, addr}
}

func (c *metricDNSClient) Query(ctx context.Context, dnsreq []byte) (*dns.Msg, error) {
	start := time.Now()
	r, err := c.client.Query(ctx, dnsreq)
	if err != nil {
		return nil, err
	}

	rc, ok := dns.RcodeToString[r.Rcode]
	if !ok {
		rc = strconv.Itoa(r.Rcode)
	}

	RequestCount.WithLabelValues(c.addr).Add(1)
	RcodeCount.WithLabelValues(rc, c.addr).Add(1)
	RequestDuration.WithLabelValues(c.addr).Observe(time.Since(start).Seconds())
	return r, nil
}

type lbDNSClient struct {
	p        policy
	timeout  time.Duration
	maxFails int
	clients  []dnsClient
}

type lbDNSClientOption func(c *lbDNSClient)

func newLoadBalanceDNSClient(clients []dnsClient, opts ...lbDNSClientOption) *lbDNSClient {
	c := &lbDNSClient{
		p:        newRandomPolicy(),
		maxFails: len(clients),
		timeout:  defaultRequestTimeout,
		clients:  clients,
	}
	for _, o := range opts {
		o(c)
	}
	if len(clients) < c.maxFails {
		c.maxFails = len(clients)
	}
	return c
}

func withLbPolicy(p policy) lbDNSClientOption {
	return func(c *lbDNSClient) {
		c.p = p
	}
}

func withLbRequestTimeout(timeout time.Duration) lbDNSClientOption {
	return func(c *lbDNSClient) {
		c.timeout = timeout
	}
}

func withLbMaxFails(maxFails int) lbDNSClientOption {
	return func(c *lbDNSClient) {
		c.maxFails = maxFails
	}
}

func (c *lbDNSClient) Query(ctx context.Context, dnsreq []byte) (*dns.Msg, error) {
	ids := c.p.List(len(c.clients))
	for i := 0; i < c.maxFails; i++ {
		r, err := c.query(ctx, dnsreq, ids[i])
		if err == nil {
			return r, nil
		}
		if i == c.maxFails-1 {
			return r, err
		}
	}
	return nil, errors.New("all queries failed")
}

func (c *lbDNSClient) query(ctx context.Context, dnsreq []byte, clientID int) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.clients[clientID].Query(ctx, dnsreq)
}
