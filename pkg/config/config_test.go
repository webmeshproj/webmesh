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

package config

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestNodeID(t *testing.T) {
	t.Parallel()

	t.Run("Default", func(t *testing.T) {
		conf := NewDefaultConfig("")
		id, err := conf.NodeID()
		if err != nil {
			t.Fatal(err)
		}
		if id != DefaultNodeID {
			t.Fatalf("expected %s, got %s", DefaultNodeID, id)
		}
		// Subsequent calls should return the same value
		id, err = conf.NodeID()
		if err != nil {
			t.Fatal(err)
		}
		if id != DefaultNodeID {
			t.Fatalf("expected %s, got %s", DefaultNodeID, id)
		}
	})

	t.Run("Preset", func(t *testing.T) {
		conf := NewDefaultConfig("test")
		id, err := conf.NodeID()
		if err != nil {
			t.Fatal(err)
		}
		if id != "test" {
			t.Fatalf("expected test, got %s", id)
		}
	})

	t.Run("BasicAuth", func(t *testing.T) {
		conf := NewDefaultConfig("")
		conf.Auth.Basic = BasicAuthOptions{
			Username: "test-basic-user",
			Password: "test-password",
		}
		id, err := conf.NodeID()
		if err != nil {
			t.Fatal(err)
		}
		if id != "test-basic-user" {
			t.Fatalf("expected test-basic-user, got %s", id)
		}
	})

	t.Run("LDAPAuth", func(t *testing.T) {
		conf := NewDefaultConfig("")
		conf.Auth.LDAP = LDAPAuthOptions{
			Username: "test-ldap-user",
			Password: "test-password",
		}
		id, err := conf.NodeID()
		if err != nil {
			t.Fatal(err)
		}
		if id != "test-ldap-user" {
			t.Fatalf("expected test-ldap-user, got %s", id)
		}
	})

	t.Run("MTLSAuth", func(t *testing.T) {
		t.Run("WithCertData", func(t *testing.T) {
			conf := NewDefaultConfig("")
			conf.Auth.MTLS = MTLSOptions{
				CertData: base64.StdEncoding.EncodeToString([]byte(testCert)),
			}
			id, err := conf.NodeID()
			if err != nil {
				t.Fatal(err)
			}
			if id != testCertCN {
				t.Fatalf("expected %s, got %s", testCertCN, id)
			}
		})

		t.Run("WithCertFile", func(t *testing.T) {
			f, err := os.CreateTemp("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())
			_, err = f.Write([]byte(testCert))
			if err != nil {
				t.Fatal(err)
			}
			err = f.Close()
			if err != nil {
				t.Fatal(err)
			}
			conf := NewDefaultConfig("")
			conf.Auth.MTLS = MTLSOptions{
				CertFile: f.Name(),
			}
			id, err := conf.NodeID()
			if err != nil {
				t.Fatal(err)
			}
			if id != testCertCN {
				t.Fatalf("expected %s, got %s", testCertCN, id)
			}
		})
	})
}

var testCertCN = "test-mtls-node"

var testCert = `
-----BEGIN CERTIFICATE-----
MIIBhDCCASqgAwIBAgIIIFcPM8pnUNowCgYIKoZIzj0EAwIwFTETMBEGA1UEAxMK
d2VibWVzaC1jYTAeFw0yMzEwMDkwODIzMzRaFw0yNDAxMDcwODIzMzRaMBkxFzAV
BgNVBAMTDnRlc3QtbXRscy1ub2RlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
YUcd9ou+wutMCorYGANgr0NWpdG0mqlUudwzh0kLw96CqoHW4kxKaVT6CPQDkJB8
FXo1Aue9BpObDQPTTKoz7qNgMF4wDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFOdr
KYofAHe1Gv8HGjHeX59Wbg1tMAoGCCqGSM49BAMCA0gAMEUCIELbjLhlVTIDopBV
pRDk03qyLXoqXgaBfNpXFT3JbXvVAiEArCafC3sy1pOrvPI7mcAyk6/xvP8nRm7t
lASd5X/aQkw=
-----END CERTIFICATE-----
`
