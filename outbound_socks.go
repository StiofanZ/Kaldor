package main

import (
	"errors"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func (u Upstream) socks5() (dialFunc, error) {
	dialer := &N.DefaultDialer{Dialer: net.Dialer{Timeout: 10 * time.Second}}
	if (u.Secret != "" && u.Username == "") || len(u.Username) > 255 || len(u.Secret) > 255 {
		return nil, errors.New("invalid SOCKS5 credentials")
	}
	c := socks.NewClient(dialer, M.ParseSocksaddr(u.Server), socks.Version5, u.Username, u.Secret)
	return c.DialContext, nil
}
