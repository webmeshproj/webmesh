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

package netutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"net"
	"net/netip"
	"time"
)

// GenerateULA generates a unique local address with a /32 prefix
// according to RFC 4193. The network is returned as a netip.Prefix.
func GenerateULA() (netip.Prefix, error) {
	secret, err := generateLocalSecret()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to generate local secret: %w", err)
	}
	return GenerateULAWithPSK(secret), nil
}

// GenerateULAWithSecret generates a unique local address with a /32 prefix
// using a pre-shared key. The network is returned as a netip.Prefix.
func GenerateULAWithPSK(psk []byte) netip.Prefix {
	sha := sha256.New()
	sha.Write(psk)
	var ip []byte
	// 1 byte prefix with L bit set
	ip = append(ip, 0xfd)
	// 5 bytes of random data
	ip = append(ip, sha.Sum(nil)[:5]...)
	// Ignore the 2 subnet bytes and do 10 bytes of zeroes
	// for client addresses
	ip = append(ip, make([]byte, 10)...)
	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 32)
}

// AssignToPrefix assigns a /112 prefix within a /32 prefix using a public key.
// It does not check that the given prefix is a valid /32 prefix.
func AssignToPrefix(prefix netip.Prefix, publicKey []byte) netip.Prefix {
	// Convert the prefix to a slice
	ip := prefix.Addr().AsSlice()
	// Take a hash of the public key
	sha := sha256.New()
	sha.Write(publicKey)
	data := sha.Sum(nil)
	// Set the client ID to the first 8 bytes of the hash
	copy(ip[6:], data[:8])
	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, 112)
}

func generateLocalSecret() ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, timeToNTP(time.Now().UTC()))
	mac, err := randomLocalMAC()
	if err != nil {
		return nil, fmt.Errorf("failed to get random MAC address: %w", err)
	}
	b = append(b, macToEUI64(mac)...)
	return b, nil
}

// timeToNTP converts a time.Time object to a 64-bit NTP time.
func timeToNTP(t time.Time) uint64 {
	nsec := uint64(t.Sub(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)))
	sec := nsec / 1000000000
	nsec = uint64(nsec-sec*1000000000) << 32
	frac := uint64(nsec / 1000000000)
	if nsec%1000000000 >= 1000000000/2 {
		frac++
	}
	return sec<<32 | frac
}

// macToEUI64 converts a MAC address to an EUI-64 identifier.
func macToEUI64(mac net.HardwareAddr) net.HardwareAddr {
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

// randomLocalMAC returns a random MAC address from the host.
func randomLocalMAC() (net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		slog.Default().Debug("failed to get network interfaces", slog.String("error", err.Error()))
		return generateMAC()
	}
	var addrs []net.HardwareAddr
	for _, interf := range interfaces {
		if interf.HardwareAddr != nil && interf.HardwareAddr[0] != 0 {
			addrs = append(addrs, interf.HardwareAddr)
		}
	}
	if len(addrs) == 0 {
		slog.Default().Debug("no network interfaces found")
		return generateMAC()
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	ri := r.Intn(len(addrs))
	return addrs[ri], nil
}

func generateMAC() (net.HardwareAddr, error) {
	// Generate a random MAC
	mac := make([]byte, 6)
	_, err := rand.Read(mac)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random MAC address: %w", err)
	}
	return mac, nil
}
