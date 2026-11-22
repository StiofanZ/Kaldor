package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/vless"
	reality "github.com/daeuniverse/outbound/transport/tls"
	M "github.com/sagernet/sing/common/metadata"
)

func (u Upstream) reality() (dialFunc, error) {
	key, err := base64.RawURLEncoding.DecodeString(u.PublicKey)
	sid, e := hex.DecodeString(u.ShortID)
	if err != nil || len(key) != 32 || e != nil || len(sid) > 8 || u.ServerName == "" {
		return nil, errors.New("invalid REALITY public key, short ID or server name")
	}
	if len(u.Secret) != 36 {
		return nil, errors.New("VLESS UUID required")
	}
	if _, err = vless.Password2Key(u.Secret); err != nil {
		return nil, errors.New("invalid VLESS UUID")
	}
	q := url.Values{"sni": {u.ServerName}, "pbk": {u.PublicKey}, "sid": {u.ShortID}, "fp": {"chrome"}}
	transport, err := reality.NewReality("reality://"+u.Server+"?"+q.Encode(), direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{}))
	if err != nil {
		return nil, errors.New("invalid REALITY settings")
	}
	v, err := vless.NewDialer(transport, protocol.Header{ProxyAddress: u.Server, Password: u.Secret, IsClient: true, Feature1: u.Flow})
	if err != nil {
		return nil, errors.New("invalid VLESS settings")
	}
	return func(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
		c, err := v.DialContext(ctx, network, d.String())
		if err != nil {
			return nil, err
		}
		if nc, ok := c.(net.Conn); ok {
			return nc, nil
		}
		return &netproxy.FakeNetConn{Conn: c, RAddr: d}, nil
	}, nil
}
