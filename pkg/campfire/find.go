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

package campfire

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
	"time"
)

// PSKSize is the size of the PSK in bytes.
const PSKSize = 32

// Now is the current time. It is a variable so it can be mocked out in tests.
var Now = time.Now

// Location is the secret and location of a campfire.
type Location struct {
	// Secret is the computed ID from the PSK.
	Secret string
	// TURNServer is the selected TURN server.
	TURNServer string
	// ExpiresAt is the time at which the campfire expires.
	ExpiresAt time.Time
}

// Expired returns a channel that is closed when the campfire expires.
func (l *Location) Expired() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		<-time.After(time.Until(l.ExpiresAt))
		close(ch)
	}()
	return ch
}

// Find finds a campfire using the given PSK and TURN servers.
// If turnServers is empty, a default list will be fetched from
// always-online-stun.
func Find(psk []byte, turnServers []string) (*Location, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("PSK must not be empty")
	} else if len(psk) != PSKSize {
		return nil, fmt.Errorf("PSK must be %d bytes", PSKSize)
	}
	if len(turnServers) == 0 {
		turnServers = GetDefaultTURNServers()
	}
	t := Now().UTC().Truncate(time.Hour)
	secret, err := computeSecret(t, psk)
	if err != nil {
		return nil, fmt.Errorf("compute secret: %w", err)
	}
	mod := len(turnServers)
	turnServer := turnServers[secret[0]%byte(mod)]
	if !strings.HasPrefix(turnServer, "turn:") {
		turnServer = "turn:" + turnServer
	}
	return &Location{
		Secret:     fmt.Sprintf("%x", secret),
		TURNServer: turnServer,
		ExpiresAt:  t.Add(time.Hour),
	}, nil
}

func computeSecret(time time.Time, psk []byte) ([]byte, error) {
	plaintext := make([]byte, aes.BlockSize+len(psk))
	timeStr := time.Format("2006-01-02 15:00:00")
	copy(plaintext, timeStr)
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aescbc := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	out := make([]byte, len(plaintext))
	aescbc.CryptBlocks(out, plaintext)
	return out, nil
}
