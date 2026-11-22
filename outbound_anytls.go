package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func (u Upstream) anyTLS(ctx context.Context, host string) (dialFunc, error) {
	if u.Secret == "" {
		return nil, errors.New("AnyTLS password required")
	}
	sni := u.ServerName
	if sni == "" {
		sni = host
	}
	tlsDial := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}}
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password: u.Secret, Logger: logger.NOP(),
		IdleSessionCheckInterval: 30 * time.Second, IdleSessionTimeout: 30 * time.Second,
		DialOut: func(ctx context.Context) (net.Conn, error) { return tlsDial.DialContext(ctx, "tcp", u.Server) },
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { client.Close() })
	return func(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
		if network == "tcp" {
			return client.CreateProxy(ctx, d)
		}
		c, err := client.CreateProxy(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return nil, err
		}
		return uot.NewLazyConn(c, uot.Request{IsConnect: true, Destination: d}), nil
	}, nil
}
