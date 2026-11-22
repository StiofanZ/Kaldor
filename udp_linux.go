package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	S "github.com/sagernet/sing/protocol/socks/socks5"
	"golang.org/x/sys/unix"
)

func socketOptions(iface string, transparent, orig bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, fd syscall.RawConn) error {
		var err error
		if e := fd.Control(func(f uintptr) {
			if iface != "" {
				err = unix.SetsockoptString(int(f), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
			if err == nil && transparent {
				err = unix.SetsockoptInt(int(f), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if err == nil && orig {
				err = unix.SetsockoptInt(int(f), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}
			if err == nil && transparent {
				err = unix.SetsockoptInt(int(f), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}
		}); e != nil {
			return e
		}
		return err
	}
}

type udpKey struct {
	src netip.AddrPort
	dst M.Socksaddr
}
type packetReply func([]byte) error
type flows struct {
	sync.Mutex
	entries map[udpKey]chan []byte
}

var udpSlots = make(chan struct{}, 256)

func (f *flows) send(ctx context.Context, e *engine, k udpKey, data []byte, openReply func() (packetReply, io.Closer, error)) {
	f.Lock()
	defer f.Unlock()
	if f.entries == nil {
		f.entries = make(map[udpKey]chan []byte)
	}
	queue := f.entries[k]
	if queue == nil {
		select {
		case udpSlots <- struct{}{}:
		default:
			return
		}
		queue = make(chan []byte, 8)
		f.entries[k] = queue
		go func() {
			defer func() { f.Lock(); delete(f.entries, k); f.Unlock(); <-udpSlots }()
			conn, err := e.dial(ctx, "udp", k.src.Addr(), k.dst, k.dst.Fqdn)
			if err != nil {
				return
			}
			defer conn.Close()
			reply, closer, err := openReply()
			if err != nil {
				return
			}
			if closer != nil {
				defer closer.Close()
			}
			flow, cancel := context.WithCancel(ctx)
			defer cancel()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				defer cancel()
				buf := make([]byte, 65535)
				for {
					n, err := conn.Read(buf)
					if err != nil || reply(buf[:n]) != nil {
						return
					}
				}
			}()
			defer func() { conn.Close(); <-finished }()
			idle := time.NewTimer(60 * time.Second)
			defer idle.Stop()
			for {
				select {
				case <-flow.Done():
					return
				case <-idle.C:
					return
				case p := <-queue:
					conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if _, err := conn.Write(p); err != nil {
						return
					}
					idle.Reset(60 * time.Second)
				}
			}
		}()
	}
	select {
	case queue <- append([]byte(nil), data...):
	default:
	}
}
func (e *engine) associate(parent context.Context, c net.Conn, r *bufio.Reader, requested M.Socksaddr, iface string) {
	source := peer(c.RemoteAddr())
	if requested.Addr.IsValid() && !requested.Addr.IsUnspecified() && requested.Addr.Unmap() != source {
		S.WriteResponse(c, S.Response{ReplyCode: 2})
		return
	}
	lc := net.ListenConfig{Control: socketOptions(iface, false, false)}
	sock, err := lc.ListenPacket(parent, "udp4", net.JoinHostPort(peer(c.LocalAddr()).String(), "0"))
	if err != nil {
		S.WriteResponse(c, S.Response{ReplyCode: 1})
		return
	}
	defer sock.Close()
	if S.WriteResponse(c, S.Response{Bind: M.SocksaddrFromNet(sock.LocalAddr())}) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() { io.Copy(io.Discard, r); cancel(); sock.Close() }()
	var table flows
	data := make([]byte, 65535)
	port := requested.Port
	for {
		n, from, err := sock.ReadFrom(data)
		if err != nil {
			return
		}
		src := M.SocksaddrFromNet(from).Unwrap().AddrPort()
		if src.Addr() != source || port != 0 && src.Port() != port || n < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
			continue
		}
		rd := bytes.NewReader(data[3:n])
		d, err := M.SocksaddrSerializer.ReadAddrPort(rd)
		if err != nil {
			continue
		}
		port = src.Port()
		table.send(ctx, e, udpKey{src, d}, data[n-rd.Len():n], func() (packetReply, io.Closer, error) {
			return func(p []byte) error {
				var b bytes.Buffer
				b.Write([]byte{0, 0, 0})
				if err := M.SocksaddrSerializer.WriteAddrPort(&b, d); err != nil {
					return err
				}
				b.Write(p)
				_, err := sock.WriteTo(b.Bytes(), from)
				return err
			}, nil, nil
		})
	}
}
func (e *engine) transparentUDP(ctx context.Context, s *net.UDPConn, iface string) error {
	var table flows
	data := make([]byte, 65535)
	oob := make([]byte, 128)
	for {
		n, o, flags, from, err := s.ReadMsgUDPAddrPort(data, oob)
		if err != nil {
			return err
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:o])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			sa, err := unix.ParseOrigDstAddr(&m)
			if err != nil {
				continue
			}
			v, ok := sa.(*unix.SockaddrInet4)
			if !ok {
				continue
			}
			dst := netip.AddrPortFrom(netip.AddrFrom4(v.Addr), uint16(v.Port))
			table.send(ctx, e, udpKey{from, M.SocksaddrFromNetIP(dst)}, data[:n], func() (packetReply, io.Closer, error) {
				dial := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(dst), Control: socketOptions(iface, true, false)}
				c, err := dial.DialContext(ctx, "udp4", from.String())
				if err != nil {
					return nil, nil, err
				}
				return func(p []byte) error { _, err := c.Write(p); return err }, c, nil
			})
			break
		}
	}
}
