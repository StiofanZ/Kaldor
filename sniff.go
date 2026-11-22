package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// Read only enough of a new transparent TCP stream to classify HTTP or TLS.
// Replay every consumed byte even if parsing times out or the format is unknown.
func sniff(c net.Conn, port uint16) (io.Reader, string) {
	var captured bytes.Buffer
	tee := io.TeeReader(io.LimitReader(c, 32768), &captured)
	c.SetReadDeadline(time.Now().Add(time.Second))
	defer c.SetReadDeadline(time.Time{})
	var host string
	switch port {
	case 80, 8080:
		req, err := http.ReadRequest(bufio.NewReader(tee))
		if err == nil {
			host = req.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
	case 443, 8443:
		hello := tls.Server(&helloConn{Conn: c, r: tee}, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) { host = info.ServerName; return nil, io.EOF }})
		_ = hello.Handshake()
	}
	return io.MultiReader(&captured, c), host
}

type helloConn struct {
	net.Conn
	r io.Reader
}

func (c *helloConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *helloConn) Write(p []byte) (int, error) { return 0, io.EOF }
