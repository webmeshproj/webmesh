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
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
)

// PSKSize is the size of the PSK in bytes.
const PSKSize = 32

// Now is the current time. It is a variable so it can be mocked out in tests.
var Now = time.Now

// Location is the secret and location of a campfire.
type Location struct {
	// PSK is the pre-shared key.
	PSK []byte
	// LocalSecret is the computed local secret from the PSK.
	LocalSecret string
	// RemoteSecret is the computed remote secret from the PSK.
	RemoteSecret string
	// TURNServer is the selected TURN server.
	TURNServer string
	// ExpiresAt is the time at which the campfire expires.
	ExpiresAt time.Time
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
	t := Now().Truncate(time.Hour)
	localsecret, err := computeSecret(t.UTC(), psk, true)
	if err != nil {
		return nil, fmt.Errorf("compute local secret: %w", err)
	}
	remotesecret, err := computeSecret(t.UTC(), psk, false)
	if err != nil {
		return nil, fmt.Errorf("compute remote secret: %w", err)
	}
	mod := len(turnServers)
	turnServer := turnServers[localsecret[0]%byte(mod)]
	return &Location{
		PSK:          psk,
		LocalSecret:  fmt.Sprintf("%x", localsecret),
		RemoteSecret: fmt.Sprintf("%x", remotesecret),
		TURNServer:   turnServer,
		ExpiresAt:    t.Add(time.Hour),
	}, nil
}

// SessionID returns the session ID.
func (l *Location) SessionID() int {
	data := base64.StdEncoding.EncodeToString([]byte(l.LocalSecret))
	sessionID := numericSession(data[0:15])
	return sessionID
}

// TURNSessionID returns the TURN session ID.
func (l *Location) TURNSessionID() string {
	data := base64.StdEncoding.EncodeToString([]byte(l.RemoteSecret))
	return data[0:15]
}

// LocalUfrag returns the local ufrag.
func (l *Location) LocalUfrag() string {
	data := base64.StdEncoding.EncodeToString([]byte(l.LocalSecret))
	return data[15:19]
}

// LocalPwd returns the local pwd.
func (l *Location) LocalPwd() string {
	data := base64.StdEncoding.EncodeToString([]byte(l.LocalSecret))
	return data[19:]
}

// RemoteUfrag returns the remote ufrag.
func (l *Location) RemoteUfrag() string {
	data := base64.StdEncoding.EncodeToString([]byte(l.RemoteSecret))
	return data[15:19]
}

// RemotePwd returns the remote pwd.
func (l *Location) RemotePwd() string {
	data := base64.StdEncoding.EncodeToString([]byte(l.RemoteSecret))
	return data[19:]
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

func computeSecret(time time.Time, psk []byte, isLocal bool) ([]byte, error) {
	plaintext := make([]byte, aes.BlockSize+len(psk))
	timeStr := time.Format("2006-01-02 15:00:00")
	copy(plaintext, timeStr)
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	iv[0] = byte(func() byte {
		if isLocal {
			return 1
		}
		return 0
	}())
	aescbc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(plaintext))
	aescbc.CryptBlocks(out, plaintext)
	return out, nil
}

func numericSession(inputString string) int {
	maxDigit := 9
	numericString := ""
	for i := 0; i < len(inputString); i++ {
		charCode := int(inputString[i])
		digit := charCode % (maxDigit + 1) // Ensure digit is between 0 and 9
		numericString += fmt.Sprintf("%d", digit)
	}
	result, _ := strconv.Atoi(numericString)
	return result
}
