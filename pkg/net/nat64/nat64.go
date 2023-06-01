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

// Package nat64 provides NAT64 support for the node using Tayga.
package nat64

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
)

const DefaultTygaExecutable = "/usr/local/sbin/tayga"

// NAT64 is a NAT64 interface.
type NAT64 struct {
	opts    *Options
	errs    chan error
	conf    *os.File
	cancel  context.CancelFunc
	confmux sync.Mutex
}

// Options are the options for a NAT64 interface.
type Options struct {
	// Name is the name of the NAT64 interface.
	Name string
	// IPv4 is the IPv4 address of the NAT64 interface.
	IPv4 netip.Addr
	// IPv6 is the IPv6 address of the NAT64 interface.
	IPv6 netip.Addr
	// IPv6Prefix is the IPv6 prefix of the NAT64 interface.
	IPv6Prefix netip.Prefix
	// TaygaExecutable is the path to the Tayga executable.
	TaygaExecutable string
}

// NewOptions creates new options for a NAT64 interface.
func NewOptions() *Options {
	return &Options{
		TaygaExecutable: DefaultTygaExecutable,
	}
}

// New creates a new NAT64 interface.
func New(opts *Options) (*NAT64, error) {
	if opts.TaygaExecutable == "" {
		opts.TaygaExecutable = DefaultTygaExecutable
	}
	if !opts.IPv4.IsValid() {
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	if !opts.IPv6.IsValid() {
		return nil, fmt.Errorf("invalid IPv6 address")
	}
	return &NAT64{
		opts: opts,
		errs: make(chan error, 3),
	}, nil
}

// Start starts the NAT64 interface.
func (n *NAT64) Start() error {
	n.confmux.Lock()
	defer n.confmux.Unlock()
	conf, err := os.CreateTemp("", "tayga.conf")
	if err != nil {
		return fmt.Errorf("failed to create temporary Tayga configuration file: %w", err)
	}
	defer conf.Close()
	n.conf = conf
	_, err = fmt.Fprintf(conf, `
tun-device %s
ipv4-addr %s
ipv6-addr %s
`, n.opts.Name, n.opts.IPv4.String(), n.opts.IPv6.String())
	if err != nil {
		return fmt.Errorf("failed to write Tayga configuration file: %w", err)
	}
	out, err := exec.Command(n.opts.TaygaExecutable, "--config", conf.Name(), "--mktun").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create Tayga interface: %w: %s", err, out)
	}
	go n.start()
	return nil
}

// Errors returns the error channel for the NAT64 interface.
func (n *NAT64) Errors() <-chan error {
	return n.errs
}

// AddMapping adds a mapping to the NAT64 interface.
func (n *NAT64) AddMapping(ipv4, ipv6 netip.Addr) error {
	if n.conf == nil {
		return fmt.Errorf("NAT64 interface not started")
	}
	n.confmux.Lock()
	defer n.confmux.Unlock()
	// Read the current configuration.
	conf, err := os.ReadFile(n.conf.Name())
	if err != nil {
		return fmt.Errorf("read configuration file: %w", err)
	}
	// Delete the file.
	if err := os.Remove(n.conf.Name()); err != nil {
		return fmt.Errorf("remove configuration file: %w", err)
	}
	// Make a new file.
	confFile, err := os.Create(n.conf.Name())
	if err != nil {
		return fmt.Errorf("create configuration file: %w", err)
	}
	defer confFile.Close()
	// Write the old configuration.
	if _, err := confFile.Write(conf); err != nil {
		return fmt.Errorf("write configuration file: %w", err)
	}
	// Write the new mapping.
	if _, err := fmt.Fprintf(confFile, "map %s %s\n", ipv4.String(), ipv6.String()); err != nil {
		return fmt.Errorf("write configuration file: %w", err)
	}
	// Restart Tayga.
	go n.restart()
	return nil
}

// DeleteMapping deletes a mapping from the NAT64 interface.
func (n *NAT64) DeleteMapping(ipv4 netip.Addr) error {
	if n.conf == nil {
		return fmt.Errorf("NAT64 interface not started")
	}
	n.confmux.Lock()
	defer n.confmux.Unlock()
	// Read the current configuration.
	conf, err := os.ReadFile(n.conf.Name())
	if err != nil {
		return fmt.Errorf("read configuration file: %w", err)
	}
	// Delete the file.
	if err := os.Remove(n.conf.Name()); err != nil {
		return fmt.Errorf("remove configuration file: %w", err)
	}
	// Make a new file.
	confFile, err := os.Create(n.conf.Name())
	if err != nil {
		return fmt.Errorf("create configuration file: %w", err)
	}
	defer confFile.Close()
	// Write the old configuration, skipping the mapping to delete.
	scanner := bufio.NewScanner(bytes.NewReader(conf))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "map "+ipv4.String()) {
			continue
		}
		if _, err := fmt.Fprintln(confFile, line); err != nil {
			return fmt.Errorf("write configuration file: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read configuration file: %w", err)
	}
	// Restart Tayga.
	go n.restart()
	return nil
}

// Stop stops the NAT64 interface.
func (n *NAT64) Stop() error {
	n.confmux.Lock()
	defer n.confmux.Unlock()
	if n.cancel != nil {
		n.cancel()
	}
	if n.conf != nil {
		os.Remove(n.conf.Name())
		n.conf = nil
	}
	link, err := netlink.LinkByName(n.opts.Name)
	if err != nil {
		// The interface doesn't exist.
		return nil
	}
	return netlink.LinkDel(link)
}

func (n *NAT64) start() {
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	cmd := exec.CommandContext(ctx, n.opts.TaygaExecutable, "--nodetach", "--config", n.conf.Name())
	err := cmd.Run()
	if err != nil {
		n.errs <- fmt.Errorf("failed to start Tayga: %w", err)
	}
}

func (n *NAT64) restart() {
	if n.cancel != nil {
		n.cancel()
	}
	n.start()
}
