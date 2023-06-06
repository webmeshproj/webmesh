/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package nat64 contains an in-process NAT64 implementation.
package nat64

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"golang.org/x/exp/slog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/webmeshproj/node/pkg/net/system"
)

// Options represents the options for creating a new NAT64.
type Options struct {
	// DeviceName is the name of the TUN device to make for NAT64.
	DeviceName string
	// MTU is the MTU of the TUN device.
	MTU int
	// IPv4Addr is the IPv4 address to assign the NAT64 device.
	IPv4Addr netip.Prefix
	// IPv6Network is the IPv6 network to use for translating to IPv4.
	IPv6Network netip.Prefix
	// IPv4Network is the IPv4 network to allow translation from IPv6.
	IPv4Network netip.Prefix
}

// NAT64 represents an in-process NAT64 implementation.
type NAT64 struct {
	opts   *Options
	dev    *water.Interface
	name   string
	closec chan struct{}
	log    *slog.Logger
}

// New creates a new NAT64.
func New(opts *Options) (*NAT64, error) {
	ctx := context.Background()
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = opts.DeviceName
	dev, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	realname := dev.Name()
	handleErr := func(err error) error {
		derr := dev.Close()
		if derr != nil {
			return fmt.Errorf("%v (and failed to close device: %v)", err, derr)
		}
		return err
	}
	err = system.SetInterfaceAddress(ctx, realname, opts.IPv4Addr)
	if err != nil {
		return nil, handleErr(fmt.Errorf("set interface address: %w", err))
	}
	err = system.ActivateInterface(ctx, realname)
	if err != nil {
		return nil, handleErr(fmt.Errorf("activate interface: %w", err))
	}
	err = system.AddRoute(ctx, realname, opts.IPv6Network)
	if err != nil {
		return nil, handleErr(fmt.Errorf("add route: %w", err))
	}
	return &NAT64{
		opts:   opts,
		dev:    dev,
		name:   realname,
		closec: make(chan struct{}),
		log:    slog.Default().With("component", "nat64", "device", realname),
	}, nil
}

// Name returns the name of the NAT64 device.
func (nat *NAT64) Name() string {
	return nat.name
}

// Close closes the NAT64 device.
func (nat *NAT64) Close() error {
	close(nat.closec)
	return nat.dev.Close()
}

// Run runs the NAT64 device.
func (nat *NAT64) Run() error {
	var frame ethernet.Frame
	for {
		select {
		case <-nat.closec:
			return nil
		default:
			frame.Resize(nat.opts.MTU)
			n, err := nat.dev.Read(frame)
			if err != nil {
				return fmt.Errorf("read: %w", err)
			}
			if n == 0 {
				continue
			}
			typ := frame[0:2]
			if typ[0] == 0x45 {
				hdr, err := ipv4.ParseHeader(frame)
				if err != nil {
					nat.log.Error("parsing IPv4 header", "error", err)
					continue
				}
				nat.log.Debug("handling IPv4 packet", "header", hdr.String())
				err = nat.handleIPv4(hdr, frame)
			} else if typ[0] == 0x60 {
				header, err := ipv6.ParseHeader(frame)
				if err != nil {
					nat.log.Error("parsing IPv6 header", "error", err)
					continue
				}
				nat.log.Debug("handling IPv6 packet", "header", header.String())
				err = nat.handleIPv6(header, frame[ipv6.HeaderLen:len(frame)-header.PayloadLen])
			} else {
				nat.log.Warn("dropping unknown packet type", "type", frame[0]&0xf0)
				continue
			}
			if err != nil {
				nat.log.Error("handling packet", "error", err)
			}
		}
	}
}

func (nat *NAT64) handleIPv4(hdr *ipv4.Header, frame ethernet.Frame) error {
	payload := frame[ipv4.HeaderLen:hdr.TotalLen]
	switch hdr.Protocol {
	case unix.IPPROTO_ICMP:
		icmpv4, err := icmp.ParseMessage(unix.IPPROTO_ICMP, payload)
		if err != nil {
			return fmt.Errorf("parse ICMP message: %w", err)
		}
		return nat.hostHandleICMPv4(hdr, frame, icmpv4)
	case unix.IPPROTO_TCP:
	case unix.IPPROTO_UDP:
	}
	return nil
}

func (nat *NAT64) handleIPv6(hdr *ipv6.Header, payload []byte) error { return nil }

func (nat *NAT64) hostHandleICMPv4(hdr *ipv4.Header, frame ethernet.Frame, icmpv4 *icmp.Message) error {
	if icmpv4.Type != ipv4.ICMPTypeEcho {
		return nil
	}
	nat.log.Debug("handling ICMPv4 echo packet", "message", icmpv4)
	return nat.hostSendICMPv4(frame, hdr, &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: icmpv4.Code,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  icmpv4.Body.(*icmp.Echo).Seq,
			Data: icmpv4.Body.(*icmp.Echo).Data,
		},
	})
}

func (nat *NAT64) hostSendICMPv4(frame ethernet.Frame, srcHeader *ipv4.Header, msg *icmp.Message) error {
	// Create an Ethernet frame
	ethernetFrame := &EthernetFrame{
		DestinationMAC: frame.Source(),
		SourceMAC:      frame.Destination(),
		EtherType:      unix.ETH_P_IP,
	}
	reply, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      srcHeader.TOS & 0x1f,
		TotalLen: ipv4.HeaderLen + len(reply),
		ID:       0,
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: unix.IPPROTO_ICMP,
		Src:      srcHeader.Dst,
		Dst:      srcHeader.Src,
	}
	hdr, err := header.Marshal()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	payload := append(hdr, reply...)
	ethernetFrame.Payload = payload
	pkt, err := ethernetFrame.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = nat.dev.Write(pkt)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func computeIPv4Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
