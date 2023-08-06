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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CampFire is the secret and location of a campfire.
type CampFire struct {
	// Secret is the computed ID from the PSK.
	Secret string
	// TURNServer is the selected TURN server.
	TURNServer string
}

// FindCampFire finds a campfire using the given PSK and TURN servers.
// If turnServers is empty, a default list will be fetched from
// always-online-stun.
func FindCampFire(psk []byte, turnServers []string) (*CampFire, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("PSK must not be empty")
	}
	if len(turnServers) == 0 {
		var err error
		turnServers, err = getDefaultTURNList()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch default TURN servers: %w", err)
		}
	}
	secret, err := computeSecret(psk)
	if err != nil {
		return nil, fmt.Errorf("compute secret: %w", err)
	}
	mod := len(turnServers)
	turnServer := turnServers[secret[0]%byte(mod)]
	return &CampFire{
		Secret:     fmt.Sprintf("%x", secret),
		TURNServer: turnServer,
	}, nil
}

func computeSecret(psk []byte) ([]byte, error) {
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	// Compute a fixed nonce for the given PSK. Otherwise, we'd need to
	// store the nonce somewhere.
	nonce := make([]byte, aesgcm.NonceSize())
	h := sha256.New()
	h.Write(psk)
	h.Sum(nonce)
	hour := time.Now().UTC().Hour()
	secret := aesgcm.Seal(nil, nonce, []byte(fmt.Sprintf("%02d:00", hour)), nil)
	return secret, nil
}

var (
	once               sync.Once
	serverFetchErr     error
	defaultTURNServers []string
	defaultTURNListURL = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt"
)

func getDefaultTURNList() ([]string, error) {
	once.Do(func() {
		resp, err := http.Get(defaultTURNListURL)
		if err != nil {
			serverFetchErr = err
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			serverFetchErr = err
			return
		}
		defaultTURNServers = strings.Split(strings.TrimSpace(string(body)), "\n")
	})
	return defaultTURNServers, serverFetchErr
}
