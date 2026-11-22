//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	S "github.com/sagernet/sing/protocol/socks/socks5"
)

func relay(c net.Conn, reader io.Reader, up net.Conn) {
	defer up.Close()
	done := make(chan struct{})
	go func() {
		io.Copy(up, reader)
		if h, ok := up.(interface{ CloseWrite() error }); ok {
			h.CloseWrite()
		} else {
			up.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		close(done)
	}()
	io.Copy(c, up)
	c.Close()
	up.Close()
	<-done
}
func peer(a net.Addr) netip.Addr { return M.SocksaddrFromNet(a).Addr.Unmap() }
func stripHop(h http.Header) {
	for _, line := range h.Values("Connection") {
		for _, key := range strings.Split(line, ",") {
			h.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}
func (e *engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	from, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid peer", 400)
		return
	}
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		d := M.ParseSocksaddr(a)
		return e.dial(ctx, n, from.Addr(), d, d.Fqdn)
	}
	if r.Method == http.MethodConnect {
		up, err := dial(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, "connection failed", 502)
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		defer c.Close()
		if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
			err = rw.Flush()
		}
		if err != nil {
			up.Close()
			return
		}
		relay(c, rw.Reader, up)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "absolute HTTP URL required", 400)
		return
	}
	req := r.Clone(r.Context())
	req.RequestURI = ""
	stripHop(req.Header)
	t := http.Transport{DialContext: dial, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second}
	defer t.CloseIdleConnections()
	resp, err := t.RoundTrip(req)
	if err != nil {
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	for key, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
func (e *engine) socks(ctx context.Context, c net.Conn, iface string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(12 * time.Second))
	r := bufio.NewReader(c)
	a, err := S.ReadAuthRequest(r)
	if err != nil {
		return
	}
	if !bytes.Contains(a.Methods, []byte{S.AuthTypeNotRequired}) {
		S.WriteAuthResponse(c, S.AuthResponse{Method: 255})
		return
	}
	if S.WriteAuthResponse(c, S.AuthResponse{}) != nil {
		return
	}
	req, err := S.ReadRequest(r)
	if err != nil {
		return
	}
	if req.Command == S.CommandUDPAssociate {
		e.associate(ctx, c, r, req.Destination, iface)
		return
	}
	if req.Command != S.CommandConnect {
		S.WriteResponse(c, S.Response{ReplyCode: S.ReplyCodeUnsupported})
		return
	}
	d := req.Destination
	up, err := e.dial(ctx, "tcp", peer(c.RemoteAddr()), d, d.Fqdn)
	if err != nil {
		S.WriteResponse(c, S.Response{ReplyCode: 1})
		return
	}
	if S.WriteResponse(c, S.Response{}) != nil {
		up.Close()
		return
	}
	c.SetDeadline(time.Time{})
	relay(c, r, up)
}
