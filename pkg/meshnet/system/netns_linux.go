// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

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

package system

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func DoInNetNS(netNS string, fn func() error) error {
	contNs, err := ns.GetNS(netNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netNS, err)
	}
	defer contNs.Close()
	return contNs.Do(func(_ ns.NetNS) error {
		return fn()
	})
}

func moveLinkIn(contNS string, ifName string) error {
	hostDev, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to find %q: %v", ifName, err)
	}
	containerNs, err := ns.GetNS(contNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", containerNs, err)
	}
	defer containerNs.Close()
	if err := netlink.LinkSetNsFd(hostDev, int(containerNs.Fd())); err != nil {
		return err
	}
	var contDev netlink.Link
	if err := containerNs.Do(func(_ ns.NetNS) error {
		var err error
		contDev, err = netlink.LinkByName(hostDev.Attrs().Name)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", hostDev.Attrs().Name, err)
		}
		// Devices can be renamed only when down
		if err = netlink.LinkSetDown(contDev); err != nil {
			return fmt.Errorf("failed to set %q down: %v", hostDev.Attrs().Name, err)
		}
		// Save host device name into the container device's alias property
		if err := netlink.LinkSetAlias(contDev, hostDev.Attrs().Name); err != nil {
			return fmt.Errorf("failed to set alias to %q: %v", hostDev.Attrs().Name, err)
		}
		// Rename container device to respect args.IfName
		if err := netlink.LinkSetName(contDev, ifName); err != nil {
			return fmt.Errorf("failed to rename device %q to %q: %v", hostDev.Attrs().Name, ifName, err)
		}
		// Bring container device up
		if err = netlink.LinkSetUp(contDev); err != nil {
			return fmt.Errorf("failed to set %q up: %v", ifName, err)
		}
		// Retrieve link again to get up-to-date name and attributes
		contDev, err = netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", ifName, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func moveLinkOut(contNS string, ifName string) error {
	containerNs, err := ns.GetNS(contNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", containerNs, err)
	}
	defer containerNs.Close()
	defaultNs, err := ns.GetCurrentNS()
	if err != nil {
		return err
	}
	defer defaultNs.Close()

	return containerNs.Do(func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to find %q: %v", ifName, err)
		}

		// Devices can be renamed only when down
		if err = netlink.LinkSetDown(dev); err != nil {
			return fmt.Errorf("failed to set %q down: %v", ifName, err)
		}

		defer func() {
			// If moving the device to the host namespace fails, set its name back to ifName so that this
			// function can be retried. Also bring the device back up, unless it was already down before.
			if err != nil {
				_ = netlink.LinkSetName(dev, ifName)
				if dev.Attrs().Flags&net.FlagUp == net.FlagUp {
					_ = netlink.LinkSetUp(dev)
				}
			}
		}()

		// Rename the device to its original name from the host namespace
		if err = netlink.LinkSetName(dev, dev.Attrs().Alias); err != nil {
			return fmt.Errorf("failed to restore %q to original name %q: %v", ifName, dev.Attrs().Alias, err)
		}

		if err = netlink.LinkSetNsFd(dev, int(defaultNs.Fd())); err != nil {
			return fmt.Errorf("failed to move %q to host netns: %v", dev.Attrs().Alias, err)
		}
		return nil
	})
}
