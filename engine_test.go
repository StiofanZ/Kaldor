package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestRuleOrder(t *testing.T) {
	src := netip.MustParsePrefix("192.0.2.7/32")
	c := Config{Default: "direct", Rules: []Rule{{Source: &src, Domain: "example.test", Outbound: "reject"}, {Port: 443, Outbound: "direct"}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, err := newEngine(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ip, host, want string }{
		{"192.0.2.7", "WWW.Example.Test.", "reject"}, {"192.0.2.8", "www.example.test", "direct"}, {"192.0.2.7", "notexample.test", "direct"},
	} {
		if got := e.route(netip.MustParseAddr(tc.ip), M.ParseSocksaddr("198.51.100.1:443"), tc.host); got != tc.want {
			t.Fatalf("%s %s: %s", tc.ip, tc.host, got)
		}
	}
}
func TestInvalidConfig(t *testing.T) {
	for _, v := range []string{`{"unknown":1}`, `{}{}`, `{"devices":["invalid"]}`} {
		if _, err := decode(strings.NewReader(v)); err == nil {
			t.Fatal("accepted", v)
		}
	}
	for _, c := range []Config{{Default: "missing"}, {Default: "direct", Rules: []Rule{{Outbound: "direct"}}}, {Default: "direct", Upstreams: []Upstream{{Name: "direct"}}}} {
		if _, err := newEngine(context.Background(), c); err == nil {
			t.Fatal("accepted invalid route")
		}
	}
}
func TestSniffReplaysClientHello(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	go tls.Client(a, &tls.Config{ServerName: "test.example"}).Handshake()
	r, host := sniff(b, 443)
	if host != "test.example" {
		t.Fatal(host)
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil || hdr[0] != 22 {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(r, data); err != nil || !bytes.Contains(data, []byte(host)) {
		t.Fatal("ClientHello not preserved", err)
	}
}
