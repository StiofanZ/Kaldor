package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func accept(ctx context.Context, l net.Listener, serve func(net.Conn)) error {
	slots := make(chan struct{}, 256)
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); serve(c) }()
		default:
			c.Close()
		}
	}
}
func (e *engine) run(ctx context.Context, lan, iface, ready string) error {
	a, err := netip.ParseAddr(lan)
	if err != nil || !a.Is4() || a.IsUnspecified() || iface == "" {
		return errors.New("LAN IPv4 address and interface required")
	}
	addr := func(port string) string { return net.JoinHostPort(lan, port) }
	lc := net.ListenConfig{Control: socketOptions(iface, false, false)}
	h, err := lc.Listen(ctx, "tcp4", addr("7890"))
	if err != nil {
		return err
	}
	defer h.Close()
	s, err := lc.Listen(ctx, "tcp4", addr("7891"))
	if err != nil {
		return err
	}
	defer s.Close()
	failure := make(chan error, 4)
	httpd := http.Server{Handler: e, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	go func() { failure <- httpd.Serve(h) }()
	go func() { failure <- accept(ctx, s, func(c net.Conn) { e.socks(ctx, c, iface) }) }()
	hasDomains := false
	for _, r := range e.cfg.Rules {
		if r.Domain != "" {
			hasDomains = true
			break
		}
	}
	if len(e.cfg.Devices) > 0 {
		lc.Control = socketOptions(iface, true, false)
		t, err := lc.Listen(ctx, "tcp4", addr("7893"))
		if err != nil {
			return err
		}
		defer t.Close()
		lc.Control = socketOptions(iface, true, true)
		u, err := lc.ListenPacket(ctx, "udp4", addr("7893"))
		if err != nil {
			return err
		}
		defer u.Close()
		go func() {
			failure <- accept(ctx, t, func(c net.Conn) {
				defer c.Close()
				d := M.SocksaddrFromNet(c.LocalAddr())
				if d.Addr.Unmap() == a && d.Port == 7893 {
					return
				}
				var input io.Reader = c
				domain := ""
				if hasDomains {
					input, domain = sniff(c, d.Port)
				}
				up, err := e.dial(ctx, "tcp", peer(c.RemoteAddr()), d, domain)
				if err == nil {
					relay(c, input, up)
				}
			})
		}()
		go func() { failure <- e.transparentUDP(ctx, u.(*net.UDPConn), iface) }()
	}
	if err = os.WriteFile(ready, []byte(version), 0600); err != nil {
		return err
	}
	defer os.Remove(ready)
	select {
	case err := <-failure:
		return err
	case <-ctx.Done():
		return nil
	}
}
