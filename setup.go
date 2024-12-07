package https

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const maxUpstreams = 15

func init() { plugin.Register("https", setup) }

func setup(c *caddy.Controller) error {
	conf, err := parseConfig(c)
	if err != nil {
		return plugin.Error("https", err)
	}

	dnsClient := setupDNSClient(conf)
	h := newHTTPS(conf.from, dnsClient, withExcept(conf.except))
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func setupDNSClient(conf *httpsConfig) dnsClient {
	var httpClient *http.Client
	if conf.httpVersion == "HTTP3.0" {
		httpClient = &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: &tls.Config{},
				QUICConfig: &quic.Config{
					Allow0RTT:       true,
					KeepAlivePeriod: time.Second * 600,
				},
			},
		}
	} else {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     conf.tlsConfig,
				ForceAttemptHTTP2:   true,
				DisableKeepAlives:   false,
				MaxConnsPerHost:     100,
				MaxIdleConnsPerHost: 100,
				MaxIdleConns:        100,
				IdleConnTimeout:     600 * time.Second,
			},
		}
	}

	clients := make([]dnsClient, len(conf.toURLs))
	for i, toURL := range conf.toURLs {
		clients[i] = newMetricDNSClient(newDoHDNSClient(httpClient, toURL), toURL)
	}

	var opts []lbDNSClientOption
	if conf.policy != nil {
		opts = append(opts, withLbPolicy(conf.policy))
	}

	// TODO request timeout, max_fail options
	return newLoadBalanceDNSClient(clients, opts...)
}

type httpsConfig struct {
	from          string
	toURLs        []string
	except        []string
	tlsConfig     *tls.Config
	tlsServerName string
	policy        policy
	httpVersion   string // Add httpVersion field
}

func parseConfig(c *caddy.Controller) (*httpsConfig, error) {
	conf := &httpsConfig{
		httpVersion: "HTTP2.0", // Default to HTTP2.0
	}
	if !c.Next() || !c.Args(&conf.from) {
		return conf, c.ArgErr()
	}

	var err error
	if conf.from, err = parseHost(conf.from); err != nil {
		return conf, err
	}

	toURLs := c.RemainingArgs()
	if len(toURLs) == 0 || len(toURLs) > maxUpstreams {
		return conf, fmt.Errorf("invalid number of TOs configured: %d", len(toURLs))
	}

	conf.toURLs, err = parseToURLs(toURLs)
	if err != nil {
		return conf, err
	}

	for c.NextBlock() {
		if err := parseBlock(c, conf); err != nil {
			return conf, err
		}
	}

	if conf.tlsServerName != "" {
		if conf.tlsConfig == nil {
			conf.tlsConfig = new(tls.Config)
		}
		conf.tlsConfig.ServerName = conf.tlsServerName
	}

	return conf, nil
}

func parseToURLs(toURLs []string) ([]string, error) {
	parsedURLs := make([]string, 0, len(toURLs))
	for _, to := range toURLs {
		toURL := "https://" + to
		if _, err := url.ParseRequestURI(toURL); err != nil {
			return nil, err
		}
		parsedURLs = append(parsedURLs, toURL)
	}
	return parsedURLs, nil
}

func parseBlock(c *caddy.Controller, conf *httpsConfig) error {
	if f, ok := parseBlockMap[c.Val()]; ok {
		return f(c, conf)
	}
	return c.Errf("unknown property '%s'", c.Val())
}

type parseBlockFunc func(*caddy.Controller, *httpsConfig) error

var parseBlockMap = map[string]parseBlockFunc{
	"except":         parseExcept,
	"tls":            parseTLS,
	"tls_servername": parseTLSServerName,
	"policy":         parsePolicy,
	"http_version":   parseHTTPVersion, // Add http_version to parseBlockMap
}

func parseExcept(c *caddy.Controller, conf *httpsConfig) error {
	except := c.RemainingArgs()
	if len(except) == 0 {
		return c.ArgErr()
	}
	for i := range except {
		var err error
		if except[i], err = parseHost(except[i]); err != nil {
			return err
		}
	}
	conf.except = except
	return nil
}

func parseHost(hostAddr string) (string, error) {
	hosts := plugin.Host(hostAddr).NormalizeExact()
	if len(hosts) == 0 {
		return "", fmt.Errorf("unable to normalize '%s'", hostAddr)
	}
	return plugin.Name(hosts[0]).Normalize(), nil
}

func parseTLS(c *caddy.Controller, conf *httpsConfig) error {
	tlsConfig, err := pkgtls.NewTLSConfigFromArgs(c.RemainingArgs()...)
	if err != nil {
		return err
	}
	conf.tlsConfig = tlsConfig
	return nil
}

func parseTLSServerName(c *caddy.Controller, conf *httpsConfig) error {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	conf.tlsServerName = args[0]
	return nil
}

func parsePolicy(c *caddy.Controller, conf *httpsConfig) error {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	switch args[0] {
	case "random":
		conf.policy = newRandomPolicy()
	case "round_robin":
		conf.policy = newRoundRobinPolicy()
	case "sequential":
		conf.policy = newSequentialPolicy()
	default:
		return c.Errf("unknown policy '%s'", args[0])
	}
	return nil
}

func parseHTTPVersion(c *caddy.Controller, conf *httpsConfig) error {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	switch args[0] {
	case "HTTP2.0", "HTTP3.0":
		conf.httpVersion = args[0]
	default:
		return c.Errf("unsupported HTTP version '%s'", args[0])
	}
	return nil
}
