//go:build linux

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

//go:embed panel.html
var panel string

//go:embed service.sh
var serviceScript string

func execute(args []string) error {
	if len(args) == 0 {
		return errors.New("command required")
	}
	if args[0] == "manager" {
		fmt.Print(serviceScript)
		return nil
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if args[0] == "page" {
		fmt.Print(strings.Replace(panel, "COMPONENT_VERSION", version, 1))
		return nil
	}
	if len(args) < 2 {
		return errors.New("configuration required")
	}
	f, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > 65536 {
		return errors.New("configuration exceeds size limit")
	}
	c, err := decode(io.LimitReader(f, 65537))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	switch args[0] {
	case "merge":
		if len(args) != 3 {
			return errors.New("previous configuration required")
		}
		old, err := os.Open(args[2])
		if err != nil {
			return err
		}
		defer old.Close()
		prev, err := decode(old)
		if err != nil {
			return err
		}
		for i, u := range c.Upstreams {
			if u.Secret != "" {
				continue
			}
			for _, p := range prev.Upstreams {
				if u.Name == p.Name && u.Protocol == p.Protocol && u.Server == p.Server && u.Username == p.Username && u.ServerName == p.ServerName && u.PublicKey == p.PublicKey && u.ShortID == p.ShortID {
					c.Upstreams[i].Secret = p.Secret
					break
				}
			}
		}
	case "view":
		for i := range c.Upstreams {
			c.Upstreams[i].Secret = ""
		}
		return json.NewEncoder(os.Stdout).Encode(c)
	}
	e, err := newEngine(ctx, c)
	if err != nil {
		return err
	}
	switch args[0] {
	case "merge":
		return json.NewEncoder(os.Stdout).Encode(c)
	case "check":
		return nil
	case "enabled":
		if !c.Enabled {
			return errors.New("disabled")
		}
		return nil
	case "devices":
		for _, v := range c.Devices {
			fmt.Println(v.Masked())
		}
		return nil
	case "serve":
		if len(args) != 5 || !c.Enabled {
			return errors.New("enabled configuration, LAN, interface and readiness path required")
		}
		return e.run(ctx, args[2], args[3], args[4])
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
