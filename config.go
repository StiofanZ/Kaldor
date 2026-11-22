package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var version = "dev"

type Config struct {
	Enabled   bool           `json:"enabled"`
	Devices   []netip.Prefix `json:"devices"`
	Upstreams []Upstream     `json:"upstreams"`
	Rules     []Rule         `json:"rules"`
	Default   string         `json:"default"`
}
type Rule struct {
	Source      *netip.Prefix `json:"source,omitempty"`
	Destination *netip.Prefix `json:"destination,omitempty"`
	Domain      string        `json:"domain_suffix,omitempty"`
	Port        uint16        `json:"port,omitempty"`
	Outbound    string        `json:"outbound"`
}

func decode(r io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid configuration JSON or unknown field")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("unexpected trailing JSON")
	}
	return c, nil
}

type engine struct {
	cfg Config
	out map[string]dialFunc
}

var namePattern = regexp.MustCompile("^[A-Za-z0-9_-]{1,48}$")

func newEngine(ctx context.Context, c Config) (*engine, error) {
	if len(c.Upstreams) > 32 || len(c.Devices) > 128 || len(c.Rules) > 512 {
		return nil, errors.New("configuration limit exceeded")
	}
	d := &N.DefaultDialer{Dialer: net.Dialer{Timeout: 10 * time.Second}}
	e := &engine{cfg: c, out: map[string]dialFunc{"direct": d.DialContext, "reject": nil}}
	for _, u := range c.Upstreams {
		if _, ok := e.out[u.Name]; ok || !namePattern.MatchString(u.Name) {
			return nil, errors.New("duplicate or invalid upstream name")
		}
		f, err := u.open(ctx)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", u.Name, err)
		}
		e.out[u.Name] = f
	}
	for _, p := range c.Devices {
		if !p.Addr().Is4() {
			return nil, errors.New("transparent device prefixes must be IPv4")
		}
	}
	if _, ok := e.out[c.Default]; !ok {
		return nil, errors.New("unknown default outbound")
	}
	for _, r := range c.Rules {
		if _, ok := e.out[r.Outbound]; !ok {
			return nil, errors.New("unknown rule outbound")
		}
		if r.Source == nil && r.Destination == nil && r.Port == 0 && r.Domain == "" {
			return nil, errors.New("empty rule")
		}
	}
	return e, nil
}
func (e *engine) route(src netip.Addr, d M.Socksaddr, domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, r := range e.cfg.Rules {
		if r.Source != nil && !r.Source.Contains(src.Unmap()) || r.Destination != nil && !r.Destination.Contains(d.Addr.Unmap()) || r.Port != 0 && r.Port != d.Port {
			continue
		}
		suffix := strings.ToLower(strings.TrimSuffix(r.Domain, "."))
		if suffix != "" && domain != suffix && !strings.HasSuffix(domain, "."+suffix) {
			continue
		}
		return r.Outbound
	}
	return e.cfg.Default
}
func (e *engine) dial(ctx context.Context, network string, src netip.Addr, d M.Socksaddr, domain string) (net.Conn, error) {
	if !d.IsValid() || d.Port == 0 {
		return nil, errors.New("invalid destination")
	}
	f := e.out[e.route(src, d, domain)]
	if f == nil {
		return nil, errors.New("rejected by rule")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return f(ctx, network, d)
}
