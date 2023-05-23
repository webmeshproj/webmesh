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

package util

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"
)

// VerifyChainOnly is a function that can be used in a TLS configuration
// to verify that the certificate chain is valid, but not the hostname.
func VerifyChainOnly(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	var cert *x509.Certificate
	for _, rawCert := range rawCerts {
		cert, _ := x509.ParseCertificate(rawCert)
		roots.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	_, err := cert.Verify(opts)
	return err
}

// Next32 returns the next IPv4 address in the given CIDR that
// is not in the given set. The bits on the returned address are
// set to the bits of the given CIDR.
func Next32(cidr netip.Prefix, set map[netip.Prefix]struct{}) (netip.Prefix, error) {
	ip := cidr.Addr().Next()
	for cidr.Contains(ip) {
		prefix := netip.PrefixFrom(ip, cidr.Bits())
		if _, ok := set[prefix]; !ok {
			return prefix, nil
		}
		ip = ip.Next()
	}
	return netip.Prefix{}, fmt.Errorf("no more addresses in %s", cidr)
}

// ToPrefixSet converts a slice of prefixes to a set.
func ToPrefixSet(addrs []string) (map[netip.Prefix]struct{}, error) {
	set := make(map[netip.Prefix]struct{})
	for _, addr := range addrs {
		ip, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, err
		}
		set[ip] = struct{}{}
	}
	return set, nil
}

// GenerateULA generates a unique local address with a /48 prefix
// according to RFC 4193. The network is returned as a netip.Prefix.
func GenerateULA() (netip.Prefix, error) {
	sha := sha1.New()

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, TimeToNTP(time.Now().UTC()))
	sha.Write(b)

	mac, err := RandomLocalMAC()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get random MAC address: %w", err)
	}
	sha.Write(MACtoEUI64(mac))

	var ip []byte
	// 8 bit prefix with L bit set
	ip = append(ip, 0xfd)
	// 40 bits of random data
	ip = append(ip, sha.Sum(nil)[15:]...)
	// subnet ID set to 0
	ip = append(ip, 0x00, 0)
	// 64 bits of zeroes, to be used for client addresses for each router
	ip = append(ip, make([]byte, 8)...)

	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 48), nil
}

// Random64 generates a random /64 prefix from a /48 prefix.
func Random64(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("prefix must be IPv6")
	}
	if prefix.Bits() != 48 {
		return netip.Prefix{}, fmt.Errorf("prefix must be /48")
	}

	// Convert the prefix to a slice
	ip := prefix.Addr().AsSlice()

	// Generate a random subnet
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var subnet [2]byte
	binary.BigEndian.PutUint16(subnet[:], uint16(r.Intn(65536)))
	ip[6] = subnet[0]
	ip[7] = subnet[1]

	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 64), nil
}

// Random96 generates a random /96 prefix from a /64 prefix.
func Random96(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("prefix must be IPv6")
	}
	if prefix.Bits() != 64 {
		return netip.Prefix{}, fmt.Errorf("prefix must be /64")
	}

	// Convert the prefix to a slice
	ip := prefix.Addr().AsSlice()

	// Set two random interface ID bytes
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var iface [2]byte
	binary.BigEndian.PutUint16(iface[:], uint16(r.Intn(65536)))
	ip[8] = iface[0]
	ip[9] = iface[1]

	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 96), nil
}

// Random128 generates a random /128 prefix from a /64 prefix.
func Random128(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("prefix must be IPv6")
	}
	if prefix.Bits() != 64 {
		return netip.Prefix{}, fmt.Errorf("prefix must be /64")
	}

	// Convert the prefix to a slice
	ip := prefix.Addr().AsSlice()

	// Set random interface bytes
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ip[8] = byte(r.Intn(256))
	ip[9] = byte(r.Intn(256))
	ip[10] = byte(r.Intn(256))
	ip[11] = byte(r.Intn(256))
	ip[12] = byte(r.Intn(256))
	ip[13] = byte(r.Intn(256))
	ip[14] = byte(r.Intn(256))
	ip[15] = byte(r.Intn(256))

	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 128), nil
}

// TimeToNTP converts a time.Time object to a 64-bit NTP time.
func TimeToNTP(t time.Time) uint64 {
	nsec := uint64(t.Sub(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)))
	sec := nsec / 1000000000
	nsec = uint64(nsec-sec*1000000000) << 32
	frac := uint64(nsec / 1000000000)
	if nsec%1000000000 >= 1000000000/2 {
		frac++
	}
	return sec<<32 | frac
}

// MACtoEUI64 converts a MAC address to an EUI-64 identifier.
func MACtoEUI64(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) != 6 {
		return mac
	}
	return net.HardwareAddr{
		mac[0] | 2,
		mac[1],
		mac[2],
		0xff,
		0xfe,
		mac[3],
		mac[4],
		mac[5],
	}
}

// GetRandomLocalMAC returns a random MAC address from the host.
func RandomLocalMAC() (net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failure to retrieve local interfaces: %w", err)
	}

	var addrs []net.HardwareAddr
	for _, interf := range interfaces {
		if interf.HardwareAddr != nil && interf.HardwareAddr[0] != 0 {
			addrs = append(addrs, interf.HardwareAddr)
		}
	}

	if len(addrs) < 1 {
		return nil, fmt.Errorf("no valid MAC addresses found")
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ri := r.Intn(len(addrs))
	return addrs[ri], nil
}
