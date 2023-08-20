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

// Package campfire implements the "camp fire" protocol.
package campfire

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"

	"github.com/pion/webrtc/v3"
)

// Protocol is the protocol name.
const Protocol = "/webmesh/campfire/1.0.0"

// CampfireChannel is a connection to one or more peers sharing the same pre-shared
// key.
type CampfireChannel interface {
	// Accept returns a connection to a peer.
	Accept() (io.ReadWriteCloser, error)
	// Close closes the camp fire.
	Close() error
	// Errors returns a channel of errors.
	Errors() <-chan error
	// Expired returns a channel that is closed when the camp fire expires.
	Expired() <-chan struct{}
	// Opened returns true if the camp fire is open.
	Opened() bool
}

// Options are options for creating or joining a new camp fire.
type Options struct {
	// PSK is the pre-shared key.
	PSK []byte
	// TURNServers is an optional list of turn servers to use.
	TURNServers []string
}

var (
	// ErrClosed is returned when the camp fire is closed.
	ErrClosed = net.ErrClosed
)

func LoadCertificateFromPEMFile(certPath string, keyPath string) (webrtc.Certificate, error) {
	var dtlsCert webrtc.Certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return dtlsCert, err
	}

	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return dtlsCert, err
	}

	// Decode PEM key
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return dtlsCert, errors.New("invalid certificate PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return dtlsCert, err
	}

	keyBlock, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "CERTIFICATE" {
		return dtlsCert, errors.New("invalid certificate PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return dtlsCert, err
	}
	dtlsCert = webrtc.CertificateFromX509(privateKey, cert)
	return dtlsCert, nil
}
