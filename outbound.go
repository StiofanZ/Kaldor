package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	M "github.com/sagernet/sing/common/metadata"
)

// Each UDP connection transports datagrams for one destination.
type dialFunc func(context.Context, string, M.Socksaddr) (net.Conn, error)

type Upstream struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Server     string `json:"server"`
	Secret     string `json:"secret,omitempty"`
	Username   string `json:"username,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	Flow       string `json:"flow,omitempty"`
}

func (u Upstream) open(ctx context.Context) (dialFunc, error) {
	host, port, err := net.SplitHostPort(u.Server)
	n, e := strconv.Atoi(port)
	if err != nil || host == "" || e != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid server or port")
	}
	switch u.Protocol {
	case "anytls":
		return u.anyTLS(ctx, host)
	case "socks5":
		return u.socks5()
	case "vless-reality":
		return u.reality()
	default:
		return nil, fmt.Errorf("unknown protocol %q", u.Protocol)
	}
}
